#pragma once
#include "attestation_handshake.hpp"
#include "sdbus_calls.hpp"
struct AttestationDeviceIface
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
    AttestationHandler& attestationHandler;
    using AFTERATTESTATION_HANDLER = std::function<void(const std::string&)>;
    AFTERATTESTATION_HANDLER onAttestationStart;
    static constexpr auto busName = "xyz.openbmc_project.attestation";
    static constexpr auto objPath =
        "/xyz/openbmc_project/attestation_requester/devices/tcp/{}";
    static constexpr auto interface = "xyz.openbmc_project.AttestationDevice";
    static constexpr auto signalName = "Attested";
    AttestationDeviceIface(
        const std::shared_ptr<sdbusplus::asio::connection>& conn,
        sdbusplus::asio::object_server& dbusServer, const ResponderInfo& rInfo,
        AttestationHandler& handler) :
        conn(conn), dbusServer(dbusServer), responderInfo(rInfo),
        attestationHandler(handler)
    {
        
        auto ifacePath = std::format(objPath, responderInfo.id);
        LOG_DEBUG("Creatign request at {}",ifacePath);
        iface = dbusServer.add_interface(ifacePath, interface);
        // test generic properties
        iface->register_method("attest", [this]() { attest(); });

        iface->register_property("remote_ip", responderInfo.ep,
                                 sdbusplus::asio::PropertyPermission::readOnly);
        iface->register_property("remote_port", responderInfo.eport,
                                 sdbusplus::asio::PropertyPermission::readOnly);
        iface->register_signal<bool>(signalName); // signal name
        LOG_DEBUG("Intialising iface");
        iface->initialize();
        LOG_DEBUG("Attestation requester iface created");
    }
    ~AttestationDeviceIface()
    {
        dbusServer.remove_interface(iface);
    }
    void setAttestationStartHandler(AFTERATTESTATION_HANDLER handler)
    {
        onAttestationStart = std::move(handler);
    }
    void attest()
    {
        attestationHandler.setEndPoint(responderInfo.ep, responderInfo.eport);
        attestationHandler.startHandshake();
    }

    void emitStatus(bool status)
    {
        LOG_DEBUG("Emitting attestation status {}", status);
        std::string path = std::format(objPath, responderInfo.id);
        auto msg = conn->new_signal(path.data(), interface, signalName);
        bool value = status;
        msg.append(value);
        msg.signal_send();
    }
};
