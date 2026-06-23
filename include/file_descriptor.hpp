#pragma once
#include <unistd.h>

namespace NSNAME
{

/**
 * @brief RAII wrapper for file descriptors (simple value-based wrapper)
 *
 * This class provides automatic resource management for POSIX file descriptors.
 * It ensures that file descriptors are properly closed when they go out of
 * scope, preventing resource leaks.
 *
 * Features:
 * - Automatic cleanup via RAII
 * - Move-only semantics (non-copyable)
 * - Maximum code reuse (all operations use reset() or release())
 * - Zero overhead (no heap allocation)
 */
class FileDescriptor
{
  public:
    FileDescriptor() : fd_(-1) {}
    explicit FileDescriptor(int fd) : fd_(fd) {}

    ~FileDescriptor()
    {
        reset();
    }

    // Non-copyable
    FileDescriptor(const FileDescriptor&) = delete;
    FileDescriptor& operator=(const FileDescriptor&) = delete;

    // Movable
    FileDescriptor(FileDescriptor&& other) noexcept : fd_(other.release()) {}

    FileDescriptor& operator=(FileDescriptor&& other) noexcept
    {
        if (this != &other)
        {
            reset(other.release());
        }
        return *this;
    }

    /**
     * @brief Reset the file descriptor, closing the current one if valid
     * @param fd New file descriptor value (default: -1)
     */
    void reset(int fd = -1)
    {
        if (fd_ != -1)
        {
            ::close(fd_);
        }
        fd_ = fd;
    }

    /**
     * @brief Get the file descriptor value
     * @return Current file descriptor
     */
    int get() const
    {
        return fd_;
    }

    /**
     * @brief Release ownership of the file descriptor
     * @return The file descriptor value (caller is responsible for closing it)
     */
    int release()
    {
        int fd = fd_;
        fd_ = -1;
        return fd;
    }

    /**
     * @brief Check if the file descriptor is valid
     * @return true if fd is not -1, false otherwise
     */
    bool isValid() const
    {
        return fd_ != -1;
    }

    explicit operator bool() const
    {
        return isValid();
    }

    int operator*() const
    {
        return fd_;
    }

  private:
    int fd_;
};

} // namespace NSNAME
