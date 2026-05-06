#pragma once
#include "name_space.hpp"

#include <systemd/sd-journal.h>

#include <format>
#include <iostream>
#include <source_location>
#include <string>
#undef LOG_WARNING
#undef LOG_ERROR
#undef LOG_DEBUG
#undef LOG_INFO
namespace NSNAME
{
enum class LogLevel
{
    DEBUG,
    INFO,
    WARNING,
    ERROR,
    CRITICAL
};
constexpr int toSystemdLevel(LogLevel level)
{
    constexpr std::array<std::pair<LogLevel, int>, 5> mapping{
        {// EMERGENCY 0
         // ALERT 1
         {LogLevel::CRITICAL, 2},
         {LogLevel::ERROR, 3},
         {LogLevel::WARNING, 4},
         // NOTICE 5
         {LogLevel::INFO, 6},
         // Note, debug here is actually mapped to info level, because OpenBMC
         // has a MaxLevelSyslog and MaxLevelStore of info, so DEBUG level will
         // never be stored.
         {LogLevel::DEBUG, 6}}};

    const auto* it = std::ranges::find_if(
        mapping, [level](const std::pair<LogLevel, int>& elem) {
            return elem.first == level;
        });

    // Unknown log level.  Just assume debug
    if (it == mapping.end())
    {
        return 6;
    }

    return it->second;
}
template <typename OutputStream>
class Logger
{
  public:
    Logger(LogLevel level, OutputStream& outputStream) :
        currentLogLevel(level), output(outputStream)
    {}
    std::string getFileName(const std::source_location& loc) const
    {
        std::string_view filename = loc.file_name();
        filename = filename.substr(filename.rfind('/'));
        if (!filename.empty())
        {
            filename.remove_prefix(1);
        }
        return std::string(filename);
    }
    void log(const std::source_location& loc, LogLevel level,
             const std::string& message) const
    {
        if (isLogLevelEnabled(level))
        {
            std::string filename = getFileName(loc);
            output << std::format("{}:{} ", filename, loc.line()) << message
                   << "\n";
            output.flush(toSystemdLevel(currentLogLevel));
        }
    }

    void setLogLevel(LogLevel level)
    {
        currentLogLevel = level;
    }

    LogLevel getLogLevel() const
    {
        return currentLogLevel;
    }

  private:
    LogLevel currentLogLevel;
    OutputStream& output;

    bool isLogLevelEnabled(LogLevel level) const
    {
        return level >= currentLogLevel;
    }
};
struct Lg2Logger
{
    std::string message;
    Lg2Logger& operator<<(const std::string& data)
    {
        message += data;
        return *this;
    }
    void flush(int level)
    {
        // Write to systemd journal using sd_journal_send
        // Requires linking with -lsystemd and including <systemd/sd-journal.h>
        sd_journal_send("MESSAGE=%s", message.c_str(), "PRIORITY=%i", level,
                        NULL);
        message.clear();
    }
};

inline Logger<Lg2Logger>& getLogger()
{
    static Lg2Logger lg2Logger;
    static Logger<Lg2Logger> logger(LogLevel::ERROR, lg2Logger);
    return logger;
}
} // namespace NSNAME

// Macros for clients to use logger
#define LOG_DEBUG(message, ...)                                                \
    NSNAME::getLogger().log(                                                   \
        std::source_location::current(), NSNAME::LogLevel::DEBUG,              \
        std::format("{} :" message, "Debug", ##__VA_ARGS__))
#define LOG_INFO(message, ...)                                                 \
    NSNAME::getLogger().log(                                                   \
        std::source_location::current(), NSNAME::LogLevel::INFO,               \
        std::format("{} :" message, "Info", ##__VA_ARGS__))
#define LOG_WARNING(message, ...)                                              \
    NSNAME::getLogger().log(                                                   \
        std::source_location::current(), NSNAME::LogLevel::WARNING,            \
        std::format("{} :" message, "Warning", ##__VA_ARGS__))
#define LOG_ERROR(message, ...)                                                \
    NSNAME::getLogger().log(                                                   \
        std::source_location::current(), NSNAME::LogLevel::ERROR,              \
        std::format("{} :" message, "Error", ##__VA_ARGS__))

#define CLIENT_LOG_DEBUG(message, ...) LOG_DEBUG(message, ##__VA_ARGS__)
#define CLIENT_LOG_INFO(message, ...) LOG_INFO(message, ##__VA_ARGS__)
#define CLIENT_LOG_WARNING(message, ...) LOG_WARNING(message, ##__VA_ARGS__)
#define CLIENT_LOG_ERROR(message, ...) LOG_ERROR(message, ##__VA_ARGS__)
