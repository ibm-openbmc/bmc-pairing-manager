#pragma once

#include "beastdefs.hpp"
#include "file_descriptor.hpp"
#include "logger.hpp"

#include <fcntl.h>
#include <linux/i2c-dev.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <boost/asio/posix/stream_descriptor.hpp>
#include <boost/asio/steady_timer.hpp>

#include <array>
#include <bit>
#include <chrono>
#include <concepts>
#include <cstring>
#include <expected>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <vector>

namespace NSNAME
{

/**
 * @brief I2C error codes
 */
enum class I2CError
{
    Success = 0,

    // --- Open/Setup Errors ---
    OpenFailed,       // Generic open failure (e.g. device node missing)
    IoctlFailed,      // ioctl(I2C_SLAVE) failed for an unclassified reason
    PermissionDenied, // Insufficient permissions to open the device (EACCES/EPERM)
    DeviceLocked,     // Device node is locked / exclusively held (EBUSY on open)
    AlreadyOpen,      // open() called on an already-open client

    // --- Address Errors ---
    InvalidAddress,      // I2C slave address is structurally invalid
    AddressOutOfRange,   // Address outside the legal I2C range (EINVAL from ioctl)

    // --- Transfer Errors ---
    WriteFailed,  // Write rejected/NACK not already covered below
    ReadFailed,   // Read rejected/NACK not already covered below
    BusError,     // I2C bus-level error: NACK, arbitration loss, line fault (EIO)
    BusBusy,      // Bus or device held by another transaction (EBUSY on transfer)
    InvalidLength, // Zero-length or otherwise invalid transfer size (EINVAL)

    // --- Buffer/Size Errors ---
    BufferTooSmall, // Caller's buffer too small to hold the full response
    BufferTooLarge, // Data exceeds the device/kernel per-message size limit

    // --- State Errors ---
    NotOpen, // Operation attempted before open() succeeded

    // --- Device / Protocol Errors ---
    DeviceNotPresent, // No ACK from device (device absent or power-off)
    Timeout,          // Operation timed out
    RetryExhausted    // Maximum retry attempts exhausted
};

/**
 * @brief Convert I2C error to string
 */
inline const char* to_string(I2CError error)
{
    switch (error)
    {
        case I2CError::Success:
            return "Success";
        case I2CError::OpenFailed:
            return "Failed to open I2C device";
        case I2CError::IoctlFailed:
            return "Failed to configure I2C slave address";
        case I2CError::PermissionDenied:
            return "Permission denied opening I2C device";
        case I2CError::DeviceLocked:
            return "I2C device locked by another process";
        case I2CError::AlreadyOpen:
            return "I2C device already open";
        case I2CError::InvalidAddress:
            return "Invalid I2C slave address";
        case I2CError::AddressOutOfRange:
            return "I2C slave address out of valid range";
        case I2CError::WriteFailed:
            return "I2C write operation failed";
        case I2CError::ReadFailed:
            return "I2C read operation failed";
        case I2CError::BusError:
            return "I2C bus error (NACK / arbitration loss / line fault)";
        case I2CError::BusBusy:
            return "I2C bus busy";
        case I2CError::InvalidLength:
            return "Invalid I2C transfer length";
        case I2CError::BufferTooSmall:
            return "Read buffer too small for response";
        case I2CError::BufferTooLarge:
            return "Write data exceeds device maximum message size";
        case I2CError::NotOpen:
            return "I2C device not open";
        case I2CError::DeviceNotPresent:
            return "I2C device not present";
        case I2CError::Timeout:
            return "I2C operation timed out";
        case I2CError::RetryExhausted:
            return "Maximum retry attempts exhausted";
        default:
            return "Unknown I2C error";
    }
}

/**
 * @brief I2C operation result type
 */
template <typename T>
using I2CResult = std::expected<T, I2CError>;

/**
 * @brief Coroutine-based I2C client for asynchronous I2C communication
 *
 * This class provides a modern C++20 coroutine-based interface for I2C
 * communication, inspired by the ibm-panel transport layer but designed
 * for use with Boost.Asio and coroutines.
 *
 * Features:
 * - Asynchronous I2C read/write operations using coroutines
 * - Automatic retry logic with configurable attempts and exponential backoff
 * - RAII-based file descriptor management
 * - Error handling with std::expected
 * - Support for both blocking and non-blocking modes
 *
 * Example usage:
 * @code
 * auto io = boost::asio::io_context();
 * auto client = I2CClient(io.get_executor(), "/dev/i2c-1", 0x50);
 *
 * co_await client.open();
 * std::vector<uint8_t> data = {0xFF, 0x80, 0x48, 0x65, 0x6C, 0x6C, 0x6F};
 * auto result = co_await client.write(data);
 * @endcode
 */
class I2CClient
{
  public:
    /**
     * @brief Construct an I2C client
     * @param executor Boost.Asio executor for async operations
     * @param devicePath Path to I2C device (e.g., "/dev/i2c-1")
     * @param slaveAddress I2C slave address (7-bit or 10-bit)
     * @param maxRetries Maximum number of retry attempts (default: 6)
     */
    I2CClient(net::any_io_executor executor, const std::string& devicePath,
              uint16_t slaveAddress, int maxRetries = 6) :
        executor_(executor), devicePath_(devicePath),
        slaveAddress_(slaveAddress), maxRetries_(maxRetries)
    {}

    /**
     * @brief Open and configure the I2C device
     * @return I2CError::Success on success, error code otherwise
     */
    net::awaitable<I2CError> open()
    {
        // Guard against double-open
        if (fd_.isValid())
        {
            LOG_WARNING("I2C device {} already open", devicePath_);
            co_return I2CError::AlreadyOpen;
        }

        // Open the I2C device file
        int fd = ::open(devicePath_.c_str(), O_RDWR | O_NONBLOCK);
        if (fd == -1)
        {
            int err = errno;
            LOG_ERROR("Failed to open I2C device {}: {} (errno: {})",
                      devicePath_, std::strerror(err), err);
            if (err == EACCES || err == EPERM)
            {
                co_return I2CError::PermissionDenied;
            }
            if (err == EBUSY)
            {
                co_return I2CError::DeviceLocked;
            }
            co_return I2CError::OpenFailed;
        }

        fd_.reset(fd);

        // Set the I2C slave address
        if (::ioctl(fd_.get(), I2C_SLAVE, slaveAddress_) == -1)
        {
            int err = errno;
            LOG_ERROR("Failed to set I2C slave address 0x{:02X} on {}: {} "
                      "(errno: {})",
                      slaveAddress_, devicePath_, std::strerror(err), err);
            if (err == EINVAL)
            {
                co_return I2CError::AddressOutOfRange;
            }
            co_return I2CError::IoctlFailed;
        }

        // Create stream descriptor for async operations
        stream_ = std::make_unique<net::posix::stream_descriptor>(
            executor_, fd_.get());

        LOG_INFO("Successfully opened I2C device {} at address 0x{:02X}",
                 devicePath_, slaveAddress_);
        co_return I2CError::Success;
    }

    /**
     * @brief Write data to the I2C device asynchronously
     * @param data Span of bytes to write
     * @return Number of bytes written on success, error code otherwise
     */
    net::awaitable<I2CResult<size_t>> write(std::span<const uint8_t> data)
    {
        if (!fd_.isValid() || !stream_)
        {
            co_return std::unexpected(I2CError::NotOpen);
        }

        if (data.empty())
        {
            LOG_WARNING("Attempted to write empty buffer to I2C device");
            co_return std::unexpected(I2CError::InvalidLength);
        }

        // Linux i2c-dev imposes a per-message limit of I2C_SMBUS_BLOCK_MAX
        // (32 bytes) for SMBus and up to 8192 bytes for raw I2C transfers.
        // Enforce the raw I2C kernel limit here to surface the error early.
        constexpr size_t kMaxI2CTransferBytes = 8192;
        if (data.size() > kMaxI2CTransferBytes)
        {
            LOG_ERROR("I2C write size {} exceeds maximum {} bytes", data.size(),
                      kMaxI2CTransferBytes);
            co_return std::unexpected(I2CError::BufferTooLarge);
        }

        // Retry loop with exponential backoff
        for (int attempt = 0; attempt < maxRetries_; ++attempt)
        {
            boost::system::error_code ec;
            size_t bytesWritten = co_await stream_->async_write_some(
                net::buffer(data.data(), data.size()),
                net::redirect_error(net::use_awaitable, ec));

            if (!ec && bytesWritten == data.size())
            {
                LOG_DEBUG("I2C write successful: {} bytes to 0x{:02X}",
                          bytesWritten, slaveAddress_);
                co_return bytesWritten;
            }

            // Classify the error before deciding whether to retry
            if (ec)
            {
                if (auto fatal = classifyTransferError(ec, "write", attempt,
                                                       data.size()))
                {
                    co_return std::unexpected(*fatal);
                }
            }

            LOG_WARNING(
                "I2C write attempt {}/{} failed: {} (wrote {}/{} bytes)",
                attempt + 1, maxRetries_, ec.message(), bytesWritten,
                data.size());

            // Wait before retry (exponential backoff: 100ms, 200ms, 400ms, ...)
            if (attempt < maxRetries_ - 1)
            {
                auto delay = std::chrono::milliseconds(100 * (1 << attempt));
                net::steady_timer timer(executor_);
                timer.expires_after(delay);
                co_await timer.async_wait(net::use_awaitable);
            }
        }

        // Distinguish bus error vs generic exhaustion on the final attempt
        LOG_ERROR("I2C write failed after {} retries to device {} at 0x{:02X}",
                  maxRetries_, devicePath_, slaveAddress_);
        co_return std::unexpected(I2CError::RetryExhausted);
    }

    /**
     * @brief Write data to the I2C device (vector overload)
     */
    net::awaitable<I2CResult<size_t>> write(const std::vector<uint8_t>& data)
    {
        co_return co_await write(std::span<const uint8_t>(data));
    }

    /**
     * @brief Read data from the I2C device asynchronously
     * @param buffer Buffer to read data into
     * @return Number of bytes read on success, error code otherwise
     */
    net::awaitable<I2CResult<size_t>> read(std::span<uint8_t> buffer)
    {
        if (!fd_.isValid() || !stream_)
        {
            co_return std::unexpected(I2CError::NotOpen);
        }

        if (buffer.empty())
        {
            LOG_WARNING("Attempted to read into empty buffer from I2C device");
            co_return std::unexpected(I2CError::InvalidLength);
        }

        // Retry loop with exponential backoff
        for (int attempt = 0; attempt < maxRetries_; ++attempt)
        {
            boost::system::error_code ec;
            size_t bytesRead = co_await stream_->async_read_some(
                net::buffer(buffer.data(), buffer.size()),
                net::redirect_error(net::use_awaitable, ec));

            if (!ec && bytesRead > 0)
            {
                LOG_DEBUG("I2C read successful: {} bytes from 0x{:02X}",
                          bytesRead, slaveAddress_);
                co_return bytesRead;
            }

            // Classify the error before deciding whether to retry
            if (ec)
            {
                if (auto fatal = classifyTransferError(ec, "read", attempt,
                                                       buffer.size()))
                {
                    co_return std::unexpected(*fatal);
                }
            }

            // Check partial read — buffer provided but device returned too few bytes
            if (!ec && bytesRead > 0 && bytesRead < buffer.size())
            {
                LOG_WARNING(
                    "I2C partial read: got {} of {} expected bytes from 0x{:02X}",
                    bytesRead, buffer.size(), slaveAddress_);
                // Partial reads are treated as retriable
            }

            LOG_WARNING("I2C read attempt {}/{} failed: {} (read {} bytes)",
                        attempt + 1, maxRetries_, ec.message(), bytesRead);

            // Wait before retry (exponential backoff)
            if (attempt < maxRetries_ - 1)
            {
                auto delay = std::chrono::milliseconds(100 * (1 << attempt));
                net::steady_timer timer(executor_);
                timer.expires_after(delay);
                co_await timer.async_wait(net::use_awaitable);
            }
        }

        LOG_ERROR("I2C read failed after {} retries from device {} at 0x{:02X}",
                  maxRetries_, devicePath_, slaveAddress_);
        co_return std::unexpected(I2CError::RetryExhausted);
    }

    /**
     * @brief Read data into a vector
     * @param size Number of bytes to read
     * @return Vector of bytes on success, error code otherwise
     */
    net::awaitable<I2CResult<std::vector<uint8_t>>> read(size_t size)
    {
        std::vector<uint8_t> buffer(size);
        auto result = co_await read(std::span<uint8_t>(buffer));

        if (!result)
        {
            co_return std::unexpected(result.error());
        }

        buffer.resize(*result);
        co_return buffer;
    }

    /**
     * @brief Write data with retry and validation
     * @param data Data to write
     * @param validateFn Optional validation function called after each write
     * @return Number of bytes written on success, error code otherwise
     */
    template <typename ValidateFn = std::nullptr_t>
    net::awaitable<I2CResult<size_t>> writeWithValidation(
        std::span<const uint8_t> data, ValidateFn validateFn = nullptr)
    {
        auto result = co_await write(data);
        if (!result)
        {
            co_return result;
        }

        if constexpr (!std::is_same_v<ValidateFn, std::nullptr_t>)
        {
            if (!validateFn())
            {
                LOG_ERROR("I2C write validation failed");
                co_return std::unexpected(I2CError::WriteFailed);
            }
        }

        co_return result;
    }

    /**
     * @brief Read a structured type from I2C
     * @tparam T Type to read (must be trivially copyable)
     * @return The read value on success, error code otherwise
     */
    template <typename T>
        requires std::is_trivially_copyable_v<T>
    net::awaitable<I2CResult<T>> readTyped()
    {
        std::vector<uint8_t> buffer(sizeof(T));
        auto result = co_await read(std::span<uint8_t>(buffer));

        if (!result)
        {
            co_return std::unexpected(result.error());
        }

        if (*result != sizeof(T))
        {
            LOG_ERROR("I2C read size mismatch: expected {}, got {}", sizeof(T),
                      *result);
            co_return std::unexpected(I2CError::ReadFailed);
        }

        T value;
        std::memcpy(&value, buffer.data(), sizeof(T));
        co_return value;
    }

    /**
     * @brief Read an integer with endianness conversion
     * @tparam T Integer type to read
     * @tparam Endian Endianness of the data (default: big-endian)
     * @return The read value on success, error code otherwise
     */
    template <typename T, std::endian Endian = std::endian::big>
        requires std::is_integral_v<T>
    net::awaitable<I2CResult<T>> readInteger()
    {
        auto result = co_await readTyped<T>();
        if (!result)
        {
            co_return result;
        }

        if constexpr (Endian != std::endian::native)
        {
            co_return std::byteswap(*result);
        }
        co_return *result;
    }

    /**
     * @brief Write a structured type to I2C
     * @tparam T Type to write (must be trivially copyable)
     * @param value The value to write
     * @return Number of bytes written on success, error code otherwise
     */
    template <typename T>
        requires std::is_trivially_copyable_v<T>
    net::awaitable<I2CResult<size_t>> writeTyped(const T& value)
    {
        std::array<uint8_t, sizeof(T)> buffer;
        std::memcpy(buffer.data(), &value, sizeof(T));
        co_return co_await write(std::span<const uint8_t>(buffer));
    }

    /**
     * @brief Write an integer with endianness conversion
     * @tparam T Integer type to write
     * @tparam Endian Endianness of the data (default: big-endian)
     * @param value The value to write
     * @return Number of bytes written on success, error code otherwise
     */
    template <typename T, std::endian Endian = std::endian::big>
        requires std::is_integral_v<T>
    net::awaitable<I2CResult<size_t>> writeInteger(T value)
    {
        if constexpr (Endian != std::endian::native)
        {
            value = std::byteswap(value);
        }
        co_return co_await writeTyped(value);
    }

    /**
     * @brief Read from a specific register
     * @tparam T Type to read from the register
     * @param reg Register address
     * @return The read value on success, error code otherwise
     */
    template <typename T>
    net::awaitable<I2CResult<T>> readRegister(uint8_t reg)
    {
        // Write register address
        auto writeResult = co_await write(std::span<const uint8_t>(&reg, 1));
        if (!writeResult)
        {
            co_return std::unexpected(writeResult.error());
        }

        // Read value
        co_return co_await readTyped<T>();
    }

    /**
     * @brief Write to a specific register
     * @tparam T Type to write to the register
     * @param reg Register address
     * @param value The value to write
     * @return Number of bytes written on success, error code otherwise
     */
    template <typename T>
    net::awaitable<I2CResult<size_t>> writeRegister(uint8_t reg, const T& value)
    {
        std::vector<uint8_t> buffer(1 + sizeof(T));
        buffer[0] = reg;
        std::memcpy(buffer.data() + 1, &value, sizeof(T));
        co_return co_await write(buffer);
    }

    /**
     * @brief Read structured data from EEPROM at a specific offset
     * @tparam T Structure type to read
     * @param offset Memory offset (2-byte addressing for EEPROMs)
     * @return The read structure on success, error code otherwise
     *
     * This function implements the standard I2C EEPROM random read protocol:
     * 1. Write 2-byte address to set EEPROM's internal read pointer
     * 2. Read data from that address
     *
     * Common use cases: VPD data, FRU information, configuration data
     */
    template <typename T>
        requires std::is_trivially_copyable_v<T>
    net::awaitable<I2CResult<T>> readEEPROM(uint16_t offset = 0)
    {
        // Write offset (2 bytes for EEPROM addressing)
        std::array<uint8_t, 2> offsetBytes = {
            static_cast<uint8_t>(offset >> 8),
            static_cast<uint8_t>(offset & 0xFF)};

        auto writeResult = co_await write(offsetBytes);
        if (!writeResult)
        {
            co_return std::unexpected(writeResult.error());
        }

        co_return co_await readTyped<T>();
    }

    /**
     * @brief Write structured data to EEPROM at a specific offset
     * @tparam T Structure type to write
     * @param offset Memory offset (2-byte addressing for EEPROMs)
     * @param data The structure to write
     * @return Number of bytes written on success, error code otherwise
     *
     * This function implements the standard I2C EEPROM write protocol:
     * Sends [Address_High, Address_Low, Data...] in a single transaction
     *
     * Common use cases: VPD data, FRU information, configuration data
     */
    template <typename T>
        requires std::is_trivially_copyable_v<T>
    net::awaitable<I2CResult<size_t>> writeEEPROM(uint16_t offset,
                                                  const T& data)
    {
        std::vector<uint8_t> buffer(2 + sizeof(T));
        buffer[0] = static_cast<uint8_t>(offset >> 8);
        buffer[1] = static_cast<uint8_t>(offset & 0xFF);
        std::memcpy(buffer.data() + 2, &data, sizeof(T));

        co_return co_await write(buffer);
    }

    /**
     * @brief Convenience alias for reading VPD data from EEPROM
     * @tparam T Structure type to read
     * @param offset Memory offset
     * @return The read structure on success, error code otherwise
     */
    template <typename T>
        requires std::is_trivially_copyable_v<T>
    net::awaitable<I2CResult<T>> readVPD(uint16_t offset = 0)
    {
        co_return co_await readEEPROM<T>(offset);
    }

    /**
     * @brief Convenience alias for writing VPD data to EEPROM
     * @tparam T Structure type to write
     * @param offset Memory offset
     * @param data The structure to write
     * @return Number of bytes written on success, error code otherwise
     */
    template <typename T>
        requires std::is_trivially_copyable_v<T>
    net::awaitable<I2CResult<size_t>> writeVPD(uint16_t offset, const T& data)
    {
        co_return co_await writeEEPROM<T>(offset, data);
    }

    /**
     * @brief Read sensor value with scaling
     * @tparam T Result type (default: float)
     * @param reg Register address
     * @param scale Scaling factor to apply
     * @return Scaled sensor value on success, error code otherwise
     */
    template <typename T = float>
    net::awaitable<I2CResult<T>> readSensor(uint8_t reg, float scale = 1.0f)
    {
        auto rawResult = co_await readRegister<uint16_t>(reg);
        if (!rawResult)
        {
            co_return std::unexpected(rawResult.error());
        }

        T scaledValue = static_cast<T>(*rawResult) * scale;
        co_return scaledValue;
    }

    /**
     * @brief Read temperature sensor (common pattern: 0.0625°C per LSB)
     * @param reg Register address
     * @return Temperature in Celsius on success, error code otherwise
     */
    net::awaitable<I2CResult<float>> readTemperature(uint8_t reg)
    {
        // Many temp sensors use 0.0625°C per LSB
        co_return co_await readSensor<float>(reg, 0.0625f);
    }

    /**
     * @brief Read multiple registers sequentially
     * @tparam T Type to read from each register
     * @tparam N Number of registers to read
     * @param startReg Starting register address
     * @return Array of read values on success, error code otherwise
     */
    template <typename T, size_t N>
    net::awaitable<I2CResult<std::array<T, N>>> readRegisters(uint8_t startReg)
    {
        std::array<T, N> results;

        for (size_t i = 0; i < N; ++i)
        {
            auto result =
                co_await readRegister<T>(static_cast<uint8_t>(startReg + i));
            if (!result)
            {
                co_return std::unexpected(result.error());
            }
            results[i] = *result;
        }

        co_return results;
    }

    /**
     * @brief Read a block of data from sequential registers
     * @tparam T Type to read from each register
     * @param startReg Starting register address
     * @param count Number of values to read
     * @return Vector of read values on success, error code otherwise
     */
    template <typename T>
    net::awaitable<I2CResult<std::vector<T>>> readRegisterBlock(
        uint8_t startReg, size_t count)
    {
        std::vector<T> results;
        results.reserve(count);

        for (size_t i = 0; i < count; ++i)
        {
            auto result =
                co_await readRegister<T>(static_cast<uint8_t>(startReg + i));
            if (!result)
            {
                co_return std::unexpected(result.error());
            }
            results.push_back(*result);
        }

        co_return results;
    }

    /**
     * @brief Check if the I2C device is open and ready
     */
    bool isOpen() const
    {
        return fd_.isValid() && stream_ != nullptr;
    }

    /**
     * @brief Get the device path
     */
    const std::string& getDevicePath() const
    {
        return devicePath_;
    }

    /**
     * @brief Get the slave address
     */
    uint16_t getSlaveAddress() const
    {
        return slaveAddress_;
    }

    /**
     * @brief Close the I2C device
     */
    void close()
    {
        stream_.reset();
        fd_.reset();
        LOG_INFO("Closed I2C device {} at address 0x{:02X}", devicePath_,
                 slaveAddress_);
    }

    /**
     * @brief Destructor - automatically closes the device
     */
    ~I2CClient()
    {
        close();
    }

    // Non-copyable
    I2CClient(const I2CClient&) = delete;
    I2CClient& operator=(const I2CClient&) = delete;

    // Movable
    I2CClient(I2CClient&&) = default;
    I2CClient& operator=(I2CClient&&) = default;

  private:
    /**
     * @brief Classify a Boost.Asio error code from an I2C transfer into a
     *        fatal I2CError, or return std::nullopt when the error is
     *        transient and the caller should retry.
     *
     * @param ec        The error code returned by async_write_some /
     *                  async_read_some.
     * @param op        Human-readable operation label ("write" / "read").
     * @param attempt   Current attempt index (0-based) for log messages.
     * @param dataSize  Number of bytes in the transfer (for EINVAL messages).
     */
    std::optional<I2CError>
        classifyTransferError(const boost::system::error_code& ec,
                              std::string_view op, int attempt,
                              size_t dataSize) const
    {
        int nativeErr = ec.value();

        if (nativeErr == EIO)
        {
            LOG_WARNING("I2C bus error on {} attempt {}/{} to 0x{:02X}: {}",
                        op, attempt + 1, maxRetries_, slaveAddress_,
                        ec.message());
            return std::nullopt; // retriable
        }
        if (nativeErr == EBUSY)
        {
            LOG_WARNING("I2C bus busy on {} attempt {}/{} to 0x{:02X}", op,
                        attempt + 1, maxRetries_, slaveAddress_);
            return std::nullopt; // retriable
        }
        if (nativeErr == EINVAL)
        {
            LOG_ERROR("Invalid I2C {} length {} to 0x{:02X}", op, dataSize,
                      slaveAddress_);
            return I2CError::InvalidLength; // fatal
        }
        if (nativeErr == ENXIO || nativeErr == ENODEV)
        {
            LOG_ERROR("I2C device 0x{:02X} not present during {}", slaveAddress_,
                      op);
            return I2CError::DeviceNotPresent; // fatal
        }

        // Unclassified error — log generically and let the retry loop handle it
        LOG_WARNING("I2C {} attempt {}/{} failed (errno {}): {}", op,
                    attempt + 1, maxRetries_, nativeErr, ec.message());
        return std::nullopt; // retriable
    }

    net::any_io_executor executor_;
    std::string devicePath_;
    uint16_t slaveAddress_;
    int maxRetries_;
    FileDescriptor fd_;
    std::unique_ptr<net::posix::stream_descriptor> stream_;
};

} // namespace NSNAME
