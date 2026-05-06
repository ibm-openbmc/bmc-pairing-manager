#pragma once
#include "logger.hpp"

#include <sdbusplus/asio/object_server.hpp>
#include <sdbusplus/bus.hpp>

#include <algorithm>
#include <cctype>
#include <memory>
#include <optional>
#include <string>

using namespace reactor;

/**
 * @brief Controller for managing debug log levels via D-Bus
 *
 * This class provides a D-Bus interface to dynamically change the log level
 * of the provisioning daemon at runtime without requiring a restart.
 */
class DebugController
{
  public:
    static constexpr auto objPath = "/xyz/openbmc_project/Debug";
    static constexpr auto interface =
        "xyz.openbmc_project.Provisioning.DebugControl";

    DebugController() = delete;
    ~DebugController() = default;
    DebugController(const DebugController&) = delete;
    DebugController& operator=(const DebugController&) = delete;
    DebugController(DebugController&&) = delete;
    DebugController& operator=(DebugController&&) = delete;

    /**
     * @brief Construct a new Debug Controller object
     *
     * @param conn D-Bus connection
     * @param objServer Object server for registering D-Bus interfaces
     */
    DebugController(std::shared_ptr<sdbusplus::asio::connection> conn,
                    std::shared_ptr<sdbusplus::asio::object_server> objServer) :
        conn(conn), objServer(objServer)
    {
        // Create the D-Bus interface
        iface = objServer->add_interface(objPath, interface);

        // Register SetLogLevel method
        iface->register_method("SetLogLevel",
                               [this](const std::string& level) -> bool {
                                   return this->setLogLevel(level);
                               });

        // Register GetLogLevel method
        iface->register_method("GetLogLevel", [this]() -> std::string {
            return this->getLogLevel();
        });

        // Initialize the interface
        iface->initialize();

        LOG_INFO("DebugController initialized at {}", objPath);
    }

  private:
    std::shared_ptr<sdbusplus::asio::connection> conn;
    std::shared_ptr<sdbusplus::asio::object_server> objServer;
    std::shared_ptr<sdbusplus::asio::dbus_interface> iface;

    /**
     * @brief Convert string to LogLevel enum
     *
     * @param levelStr String representation of log level
     * @return std::optional<LogLevel> LogLevel if valid, nullopt otherwise
     */
    std::optional<LogLevel> stringToLogLevel(const std::string& levelStr)
    {
        if (levelStr == "DEBUG")
        {
            return LogLevel::DEBUG;
        }
        else if (levelStr == "INFO")
        {
            return LogLevel::INFO;
        }
        else if (levelStr == "WARNING")
        {
            return LogLevel::WARNING;
        }
        else if (levelStr == "ERROR")
        {
            return LogLevel::ERROR;
        }
        else if (levelStr == "CRITICAL")
        {
            return LogLevel::CRITICAL;
        }
        return std::nullopt;
    }

    /**
     * @brief Convert LogLevel enum to string
     *
     * @param level LogLevel enum value
     * @return std::string String representation of log level
     */
    std::string logLevelToString(LogLevel level)
    {
        switch (level)
        {
            case LogLevel::DEBUG:
                return "DEBUG";
            case LogLevel::INFO:
                return "INFO";
            case LogLevel::WARNING:
                return "WARNING";
            case LogLevel::ERROR:
                return "ERROR";
            case LogLevel::CRITICAL:
                return "CRITICAL";
            default:
                return "UNKNOWN";
        }
    }

    /**
     * @brief Set the log level
     *
     * @param levelStr String representation of desired log level
     * @return true if log level was successfully set
     * @return false if invalid log level string provided
     */
    bool setLogLevel(const std::string& levelStr)
    {
        // Convert to uppercase for case-insensitive comparison
        std::string upperLevel = levelStr;
        std::transform(upperLevel.begin(), upperLevel.end(), upperLevel.begin(),
                       [](unsigned char c) { return std::toupper(c); });

        auto level = stringToLogLevel(upperLevel);
        if (!level)
        {
            LOG_ERROR("Invalid log level: {}", levelStr);
            return false;
        }

        getLogger().setLogLevel(*level);
        LOG_INFO("Log level changed to: {}", upperLevel);
        return true;
    }

    /**
     * @brief Get the current log level
     *
     * @return std::string String representation of current log level
     */
    std::string getLogLevel()
    {
        LogLevel currentLevel = getLogger().getLogLevel();
        return logLevelToString(currentLevel);
    }
};
