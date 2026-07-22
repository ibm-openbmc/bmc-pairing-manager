#pragma once

#include "logger.hpp"

#include <filesystem>
#include <fstream>
#include <ranges>
#include <sstream>
#include <string>
#include <vector>

static constexpr auto PEER_HOSTNAME = "bmc.peer";
static constexpr auto ETC_HOSTS_PATH = "/etc/hosts";

/**
 * @brief Write or overwrite the bmc.peer entry in /etc/hosts.
 *
 * Reads the current /etc/hosts, removes any existing line that already
 * maps to PEER_HOSTNAME, appends the new mapping, then atomically replaces
 * the file by writing to a temp path and renaming.
 *
 * @param ip  The IPv4 (or IPv6) address to map to bmc.peer.
 * @return true on success, false on any I/O failure.
 */
inline bool updateEtcHosts(const std::string& ip)
{
    const std::string hostsPath = ETC_HOSTS_PATH;
    const std::string tmpPath = std::string(ETC_HOSTS_PATH) + ".tmp";

    // Read existing content, stripping any previous bmc.peer line.
    std::vector<std::string> lines;
    {
        std::ifstream in(hostsPath);
        if (in.is_open())
        {
            // Collect all lines that do NOT contain PEER_HOSTNAME as a token.
            auto noPeer = [](const std::string& line) {
                auto tokens = line | std::views::split(' ') |
                              std::views::transform([](auto rng) {
                                  return std::string_view(rng.begin(), rng.end());
                              });
                return std::ranges::none_of(tokens, [](std::string_view tok) {
                    return tok == PEER_HOSTNAME;
                });
            };

            std::string line;
            while (std::getline(in, line))
            {
                if (noPeer(line))
                {
                    lines.push_back(line);
                }
            }
        }
    }

    // Append the fresh entry.
    lines.push_back(ip + "\t" + PEER_HOSTNAME);

    // Write to a temp file then rename for atomicity.
    {
        std::ofstream out(tmpPath);
        if (!out.is_open())
        {
            LOG_ERROR("Failed to open {} for writing", tmpPath);
            return false;
        }
        for (const auto& line : lines)
        {
            out << line << '\n';
        }
        if (!out)
        {
            LOG_ERROR("Write error on {}", tmpPath);
            return false;
        }
    }

    std::error_code ec;
    std::filesystem::rename(tmpPath, hostsPath, ec);
    if (ec)
    {
        LOG_ERROR("Failed to rename {} -> {}: {}", tmpPath, hostsPath,
                  ec.message());
        return false;
    }

    LOG_INFO("Updated {}: {} -> {}", hostsPath, ip, PEER_HOSTNAME);
    return true;
}
