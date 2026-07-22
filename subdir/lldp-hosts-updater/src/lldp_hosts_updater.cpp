// Watches the LLDP neighbour D-Bus interface for a management IP address
// and writes/overwrites a "bmc.peer <ip>" entry in /etc/hosts so that
// systemd-resolved resolves the peer by name without a DNS lookup.

#include "command_line_parser.hpp"
#include "hosts_updater.hpp"
#include "lldp_neighbour_handlers.hpp"
#include "logger.hpp"
#include "sdbus_calls.hpp"

#include <boost/asio.hpp>
#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/bus/match.hpp>

#include <format>
#include <string>

namespace net = boost::asio;
using namespace reactor;

static constexpr auto DEFAULT_IFACE = "eth2";

/**
 * @brief Coroutine called each time a neighbour IP is discovered via LLDP.
 *
 * Updates /etc/hosts with the new IP → bmc.peer mapping and continues
 * watching so future address changes are also applied.
 */
static net::awaitable<void> onNeighbourFound(const std::string& address,
                                             const std::string& /*name*/)
{
    LOG_INFO("LLDP neighbour discovered: {}", address);
    if (!updateEtcHosts(address))
    {
        LOG_ERROR("Failed to update /etc/hosts with address {}", address);
    }
    co_return;
}

int main(int argc, const char* argv[])
{
    auto [iface] = getArgs(parseCommandline(argc, argv), "--iface,-i");
    std::string ifaceName = iface ? std::string(*iface) : DEFAULT_IFACE;

    auto& logger = getLogger();
    logger.setLogLevel(LogLevel::INFO);

    net::io_context io_context;
    auto conn = std::make_shared<sdbusplus::asio::connection>(io_context);

    // Shared handler used by both the signal watcher and the startup poll.
    auto neighbourHandler = [](const std::string& address,
                               const std::string& name) -> net::awaitable<void> {
        co_await onNeighbourFound(address, name);
    };

    // Fallback: read existing LLDP state immediately at startup.
    auto fallbackHandler =
        makeNeighbourUpdateHandler(conn, ifaceName, neighbourHandler);

    // Subscribe to future InterfacesAdded signals on the LLDP receive path.
    DbusSignalWatcher<sdbusplus::message_t>::watch(
        io_context, conn,
        makeNeighbourDiscoveryHandler(neighbourHandler,
                                      std::move(fallbackHandler)),
        sdbusplus::bus::match::rules::interfacesAddedAtPath(
            std::format(LLDP_REC_PATH, ifaceName)));

    // Also trigger an initial poll so an already-present neighbour is handled.
    net::co_spawn(
        io_context,
        makeNeighbourUpdateHandler(conn, ifaceName, neighbourHandler),
        net::detached);

    LOG_INFO("lldp-hosts-updater started, watching interface {}", ifaceName);
    io_context.run();
    return 0;
}
