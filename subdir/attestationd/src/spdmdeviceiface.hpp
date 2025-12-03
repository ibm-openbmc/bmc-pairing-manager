#pragma once
#include "sdbus_calls.hpp"
#include "spdm_handshake.hpp"
struct SpdmDeviceIface
{
    std::shared_ptr<sdbusplus::asio::connection> conn;
    sdbusplus::asio::object_server& dbusServer;
    std::shared_ptr<sdbusplus::asio::dbus_interface> iface;
    struct ResponderInfo
    {
        std::string id;
        std::string ep;
        std::string eport;
    };
    ResponderInfo responderInfo;
    SpdmHandler& spdmHandler;
    using AFTERATTESTATION_HANDLER = std::function<void(const std::string&)>;
    AFTERATTESTATION_HANDLER onAttestationStart;
    static constexpr auto busName = "xyz.openbmc_project.spdm";
    static constexpr auto objPath =
        "/xyz/openbmc_project/spdm_requester/devices/tcp/{}";
    static constexpr auto interface = "xyz.openbmc_project.SpdmDevice";
    static constexpr auto signalName = "Attested";
    SpdmDeviceIface(const std::shared_ptr<sdbusplus::asio::connection>& conn,
                    sdbusplus::asio::object_server& dbusServer,
                    const ResponderInfo& rInfo, SpdmHandler& handler) :
        conn(conn), dbusServer(dbusServer), responderInfo(rInfo),
        spdmHandler(handler)
    {
        auto ifacePath = std::format(objPath, responderInfo.id);
        iface = dbusServer.add_interface(ifacePath, interface);
        // test generic properties
        iface->register_method("attest", [this]() { attest(); });

        iface->register_property("remote_ip", responderInfo.ep,
                                 sdbusplus::asio::PropertyPermission::readOnly);
        iface->register_property("remote_port", responderInfo.eport,
                                 sdbusplus::asio::PropertyPermission::readOnly);
        iface->register_signal<bool>(signalName); // signal name
        iface->initialize();
    }
    ~SpdmDeviceIface()
    {
        dbusServer.remove_interface(iface);
    }
    void setAttestationStartHandler(AFTERATTESTATION_HANDLER handler)
    {
        onAttestationStart = std::move(handler);
    }
    void attest()
    {
        spdmHandler.setEndPoint(responderInfo.ep, responderInfo.eport);
        spdmHandler.startHandshake();
    }

    void emitStatus(bool status)
    {
        LOG_DEBUG("Emitting spdm status {}", status);
        std::string path = std::format(objPath, responderInfo.id);
        auto msg = conn->new_signal(path.data(), interface, signalName);
        bool value = status;
        msg.append(value);
        msg.signal_send();
    }
};
