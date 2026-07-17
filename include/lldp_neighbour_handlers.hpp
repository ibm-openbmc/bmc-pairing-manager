#pragma once

#include "dbusproperty_watcher.hpp"
#include "logger.hpp"
#include "sdbus_calls.hpp"

#include <boost/asio.hpp>
#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/message.hpp>

#include <format>
#include <optional>
#include <string>

namespace net = boost::asio;

// Define LLDP constants
static constexpr auto LLDP_SVC = "xyz.openbmc_project.LLDP";
static constexpr auto LLDP_REC_PATH =
    "/xyz/openbmc_project/network/lldp/{}/receive";
static constexpr auto LLDP_INTF = "xyz.openbmc_project.Network.LLDP.TLVs";

/**
 * @brief Creates a handler for LLDP neighbor discovery via D-Bus signal
 *
 * This function creates a coroutine handler that processes LLDP InterfacesAdded
 * signals to discover new neighbors on the network. When a new LLDP neighbor is
 * detected, it extracts the management IP address and system name, then invokes
 * the provided handler callback.
 *
 * @tparam Handler A callable that accepts (const std::string& address, const
 * std::string& name) and returns net::awaitable<void>
 * @param handler The callback to invoke when a neighbor is discovered
 * @return A coroutine handler for D-Bus signal processing
 */
template <typename Handler>
auto makeNeighbourDiscoveryHandler(Handler handler,
                                   std::function<void()> fallback = {})
{
    return [handler = std::move(handler), fallback = std::move(fallback)](
               const boost::system::error_code& ec,
               std::optional<sdbusplus::message_t> m) -> net::awaitable<void> {
        if (!m)
        {
            LOG_ERROR("Failed to get LLDP interface signal change");
            co_return;
        }
        reactor::InterfaceMap interfaces;
        sdbuscompat::object_path objPath;
        m->read(objPath, interfaces);
        auto it = interfaces.find(LLDP_INTF);
        if (it == interfaces.end())
        {
            LOG_ERROR("Failed to find LLDP interface in signal");
            co_return;
        }

        auto propMap = it->second;
        auto [ec1, address, name] =
            reactor::getPropertiesFromMap<std::string, std::string>(
                propMap, "ManagementAddressIPv4", "SystemName");
        if (ec1)
        {
            LOG_ERROR("Failed to get LLDP properties: {}", ec.message());
            co_return;
        }
        if (address.empty() || name.empty())
        {
            LOG_ERROR("LLDP Address or Name is empty");
            if (fallback)
            {
                LOG_DEBUG("Calling fallback for fetching Address");
                fallback();
            }
            co_return;
        }

        co_await handler(address, name);
        co_return;
    };
}

/**
 * @brief Creates a handler to update neighbor details from existing LLDP data
 *
 * This function creates a coroutine that queries the current LLDP properties
 * for a specific network interface and invokes the provided handler with the
 * discovered neighbor information. This is useful for initializing neighbor
 * information at startup or when reconnecting.
 *
 * @tparam Handler A callable that accepts (const std::string& address, const
 * std::string& name) and returns net::awaitable<void>
 * @param conn Shared pointer to the D-Bus connection
 * @param ifaceName The network interface name (e.g., "eth0")
 * @param handler The callback to invoke with the neighbor information
 * @return A coroutine that queries and processes LLDP neighbor data
 */
template <typename Handler>
auto makeNeighbourUpdateHandler(
    std::shared_ptr<sdbusplus::asio::connection> conn,
    const std::string& ifaceName, Handler handler)
{
    return [handler = std::move(handler), conn,
            ifaceName]() -> net::awaitable<void> {
        auto [ec, properties] = co_await reactor::getAllProperties(
            *conn, LLDP_SVC, std::format(LLDP_REC_PATH, ifaceName), LLDP_INTF);
        if (ec)
        {
            LOG_ERROR("Failed to get LLDP property: {}", ec.message());
            co_return;
        }
        auto [ec1, address, name] =
            reactor::getPropertiesFromMap<std::string, std::string>(
                properties, "ManagementAddressIPv4", "SystemName");
        if (ec1)
        {
            LOG_ERROR("Failed to get LLDP properties: {}", ec.message());
            co_return;
        }
        if (address.empty() || name.empty())
        {
            LOG_ERROR("LLDP Address or Name is empty");
            co_return;
        }
        co_await handler(address, name);
        co_return;
    };
}
