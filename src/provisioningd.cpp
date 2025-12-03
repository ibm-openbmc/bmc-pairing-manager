#include "bmcresponder.hpp"
#include "cert_generator.hpp"
#include "command_line_parser.hpp"
#include "dbusproperty_watcher.hpp"
#include "provisioning_object.hpp"
#include "ssl_functions.hpp"
#include "tcp_client.hpp"
#include "tcp_server.hpp"

#include <unistd.h>

#include <nlohmann/json.hpp>

#include <fstream>
#include <iostream>
static constexpr auto SPDM_SVC = "xyz.openbmc_project.spdm";
static constexpr auto SPDM_DEVICE_PATH =
    "/xyz/openbmc_project/spdm_requester/devices/tcp/{}";
static constexpr auto SPDM_RES_PATH =
    "/xyz/openbmc_project/spdm_responder/tcp/{}";
static constexpr auto SPDM_DEVICE_INTF = "xyz.openbmc_project.SpdmDevice";
static constexpr auto SPDM_RES_INTF = "xyz.openbmc_project.SpdmResponder";
static constexpr auto SPDM_PROP = "Status";
static constexpr auto SPDM_REQ_SIGNAL = "Attested";
static constexpr auto SPDM_RES_SIGNAL = "Attested";
static constexpr auto LLDP_SVC = "xyz.openbmc_project.LLDP";
static constexpr auto LLDP_PATH = "/xyz/openbmc_project/network/lldp/{}";
static constexpr auto LLDP_INTF = "xyz.openbmc_project.Network.LLDP.TLVs";
static constexpr auto LLDP_PROP = "ManagementAddressIPv4";
static constexpr auto LLDP_REC_PATH =
    "/xyz/openbmc_project/network/lldp/{}/receive";

using DbusObjectPath = std::string;
using DbusInterface = std::string;
using PropertyValue = std::string;
using DbusService = std::string;

net::awaitable<void> waitFor(net::io_context& io_context,
                             std::chrono::seconds duration)
{
    net::steady_timer timer(io_context, duration);
    co_await timer.async_wait(net::use_awaitable);
}
net::awaitable<std::optional<std::string>> getRemoteIp(
    sdbusplus::asio::connection& conn, const std::string& iface)
{
    auto [ec, propVal] = co_await getProperty<std::string>(
        conn, LLDP_SVC, std::format(LLDP_REC_PATH, iface), LLDP_INTF,
        LLDP_PROP);
    if (ec)
    {
        LOG_ERROR("Failed to get LLDP property: {}", ec.message());
        co_return std::nullopt;
    }
    co_return std::optional(propVal);
}
net::awaitable<bool> monitorBmc(net::io_context& io_context, TcpClient& client,
                                bool needping = false)
{
    std::string message("Hello");
    auto [ec, bytes] = co_await client.write(net::buffer(message));
    if (ec)
    {
        LOG_ERROR("Connect error: {}", ec.message());
        co_return false;
    }
    std::array<char, 1024> data{0};
    while (true)
    {
        auto [ec, bytes] = co_await client.read(net::buffer(data));
        if (ec)
        {
            if (ec == net::error::operation_aborted)
            {
                continue;
            }
            LOG_ERROR("Receive error: {}", ec.message());
            co_return false;
        }
        LOG_INFO("Received from BMC: {}", std::string(data.data(), bytes));
        if (needping)
        {
            std::string ping("ping");
            auto [ecw, bytesw] = co_await client.write(net::buffer(ping));
            if (ecw)
            {
                LOG_ERROR("Send error: {}", ecw.message());
                co_return false;
            }
            co_await waitFor(io_context, 5s);
        }
    }
    co_return false;
}
net::awaitable<boost::system::error_code> connect(
    TcpClient& client, const std::string& ip, short port)
{
    int retryCount = 3;
    while (retryCount--)
    {
        auto ec = co_await client.connect(ip, std::to_string(port));

        if (ec)
        {
            if (ec.category() ==
                boost::asio::error::ssl_category) // check SSL error
            {
                LOG_ERROR("SSL connect error: {} {}", ip, ec.message());
                co_return ec;
            }

            if (retryCount <= 0)
            {
                LOG_ERROR("Connect error: {} {}", ip, ec.message());
                co_return ec;
            }

            // retry after delay
            boost::asio::steady_timer timer(
                co_await boost::asio::this_coro::executor);
            timer.expires_after(std::chrono::seconds(5));
            co_await timer.async_wait(net::use_awaitable);
            continue;
        }
        break;
    }
    co_return boost::system::error_code{};
}
net::awaitable<void> tryConnect(net::io_context& io_context,
                                const std::string& ip, short port,
                                ProvisioningController& controller)
{
    controller.setPeerConnected(
        ProvisioningIface::PeerConnectionStatus::InProgress);
    LOG_DEBUG("Trying peer connection");
    auto sslCtx = getClientContext();
    if (!sslCtx)
    {
        LOG_ERROR("ssl context is not available");
        controller.setPeerConnected(
            ProvisioningIface::PeerConnectionStatus::NotConnected);
        co_return;
    }
    TcpClient client(io_context.get_executor(), *sslCtx);
    auto ec = co_await connect(client, ip, port);
    if (ec)
    {
        controller.setPeerConnected(
            ProvisioningIface::PeerConnectionStatus::NotConnected);
        co_return;
    }
    controller.setPeerConnected(
        ProvisioningIface::PeerConnectionStatus::Connected);
    co_await monitorBmc(io_context, client);
    controller.setPeerConnected(
        ProvisioningIface::PeerConnectionStatus::NotConnected);
}

std::shared_ptr<BmcResponder> makeBmcResponder(
    net::io_context& ctx, ssl::context sslCtx, short port,
    ProvisioningController& controller)
{
    auto bmcResponder =
        std::make_shared<BmcResponder>(ctx, std::move(sslCtx), port);

    bmcResponder->onConnectionChange([&controller](bool connected) {
        controller.setPeerConnected(
            connected ? ProvisioningIface::PeerConnectionStatus::Connected
                      : ProvisioningIface::PeerConnectionStatus::NotConnected);
    });
    return bmcResponder;
}
net::awaitable<void> tryConnectIfNeighbourFound(
    net::io_context& io_context,
    std::shared_ptr<sdbusplus::asio::connection> conn,
    ProvisioningController& controller, short rport, const std::string& iface)
{
    auto propVal = co_await getRemoteIp(*conn, iface);
    if (propVal)
    {
        LOG_INFO("LLDP ManagementAddressIPv4: {}", *propVal);
        co_await tryConnect(io_context, *propVal, rport, controller);
    }
    co_return;
}
net::awaitable<void> onNeighbhorFound(
    net::io_context& io_context, ProvisioningController& controller,
    short rport, const boost::system::error_code& ec,
    std::optional<std::string> ip)
{
    if (ec)
    {
        co_return;
    }
    LOG_INFO("LLDP Neighbour IP found: {}", *ip);
    if (controller.peerConnected() ==
        ProvisioningIface::PeerConnectionStatus::Connected)
    {
        LOG_INFO("Peer already connected, skipping connection attempt");
        co_return;
    }
    co_await tryConnect(io_context, *ip, rport, controller);
    co_return;
}
net::awaitable<void> onSpdmStateChange(
    net::io_context& io_context, short port, ProvisioningController& controller,
    std::shared_ptr<BmcResponder>& bmcResponder,
    const boost::system::error_code& ec, std::optional<bool> val)
{
    if (ec)
    {
        co_return;
    }
    controller.setProvisioned(*val);
    if (*val)
    {
        LOG_INFO("SPDM provisioning completed successfully");
        bmcResponder.reset();
        auto sslContext = getServerContext();
        if (!sslContext)
        {
            LOG_ERROR("ssl context is not available");
            co_return;
        }
        bmcResponder = makeBmcResponder(io_context, std::move(*sslContext),
                                        port, controller);
        co_return;
    }
    LOG_INFO("SPDM provisioning completed with failed status");
}
net::awaitable<void> startSpdm(
    sdbusplus::asio::connection& conn,
    std::shared_ptr<DbusSignalWatcher<bool>> watcher, net::io_context& ioc,
    short port, const std::string& iface, ProvisioningController& controller,
    std::shared_ptr<BmcResponder>& bmcResponder, const std::string& deviceName)
{
    try
    {
        // This method would start the SPDM provisioning process.
        // Implementation would depend on the specific requirements.
        LOG_INFO("Starting SPDM provisioning");
        auto device = std::format(SPDM_DEVICE_PATH, deviceName);
        auto [ec, msg] =
            co_await awaitable_dbus_method_call<sdbusplus::message_t>(
                conn, SPDM_SVC, device, SPDM_DEVICE_INTF, "attest");
        if (ec)
        {
            LOG_ERROR("Failed to start spdm: {}", ec.message());
        }
        auto val = co_await watcher->watchOnce(30s);
        if (val && *val)
        {
            controller.peerProvisioned(true);
            auto ip = co_await getRemoteIp(conn, iface);
            if (ip)
            {
                net::co_spawn(ioc,
                              std::bind_front(tryConnect, std::ref(ioc), *ip,
                                              port, std::ref(controller)),
                              net::detached);
                co_return;
            }
        }
        LOG_ERROR("SPDM provisioning failed or timed out");
        controller.peerProvisioned(false);
    }
    catch (std::exception& e)
    {
        LOG_ERROR("SPDM provisioning failed {}", e.what());
    }
}
nlohmann::json loadConfig(const std::string& configPath)
{
    std::ifstream confFile(configPath);
    if (confFile)
    {
        return nlohmann::json::parse(confFile);
    }
    return nlohmann::json{
        {"port", 8090}, {"cert_root", "/"}, {"interface_id", "eth1"}};
}
int main(int argc, const char* argv[])
{
    try
    {
        auto& logger = getLogger();
        logger.setLogLevel(LogLevel::DEBUG);
        Tpm2::getInstance(); // Initialize TPM2 provider
        net::io_context io_context;

        auto confJson = loadConfig("/var/provisioning/provisioning.conf");
        auto port = confJson.value("port", 8090);
        cert_root = confJson.value("cert_root", std::string{"/"});
        auto iface = confJson.value("interface_id", std::string{"eth2"});

        auto conn = std::make_shared<sdbusplus::asio::connection>(io_context);
        ProvisioningController controller(io_context, conn);
        conn->request_name(ProvisioningController::busName);
        std::shared_ptr<BmcResponder> bmcResponder;
        auto sslCtx = getServerContext();
        if (sslCtx)
        {
            bmcResponder = makeBmcResponder(io_context, std::move(*sslCtx),
                                            port, controller);
        }
        controller.setProvisionHandler([&](const std::string& deviceName) {
            LOG_INFO("Provisioning started");
            auto watcherPtr = std::make_shared<DbusSignalWatcher<bool>>(
                conn, SPDM_DEVICE_INTF, SPDM_REQ_SIGNAL);
            net::co_spawn(io_context,
                          std::bind_front(startSpdm, std::ref(*conn),
                                          watcherPtr, std::ref(io_context),
                                          port, iface, std::ref(controller),
                                          std::ref(bmcResponder), deviceName),
                          net::detached);
        });

        DbusSignalWatcher<bool>::watch(
            io_context, conn,
            std::bind_front(onSpdmStateChange, std::ref(io_context), port,
                            std::ref(controller), std::ref(bmcResponder)),
            SPDM_RES_INTF, SPDM_RES_SIGNAL);
        DbusPropertyWatcher<std::string>::watch(
            io_context, conn,
            std::bind_front(onNeighbhorFound, std::ref(io_context),
                            std::ref(controller), port),
            std::format(LLDP_REC_PATH, iface), LLDP_INTF, LLDP_PROP);

        net::co_spawn(
            io_context,
            std::bind_front(tryConnectIfNeighbourFound, std::ref(io_context),
                            conn, std::ref(controller), port, iface),
            net::detached);
        io_context.run();
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("Exception: {}", e.what());
        return 1;
    }
}
