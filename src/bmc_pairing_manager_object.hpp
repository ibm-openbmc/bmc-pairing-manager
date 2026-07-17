#pragma once
#include "logger.hpp"
#include "pic_controller.hpp"
#include "sdbus_calls.hpp"

#include <xyz/openbmc_project/Common/error.hpp>
#include <xyz/openbmc_project/Provisioning/Provisioning/server.hpp>
using namespace reactor;

using namespace sdbusplus::server::xyz::openbmc_project::provisioning;
using ProvisioningIface =
    sdbusplus::server::xyz::openbmc_project::provisioning::Provisioning;
using Ifaces = sdbusplus::server::object_t<ProvisioningIface>;
using InsufficientPermission =
    sdbusplus::xyz::openbmc_project::Common::Error::InsufficientPermission;
using InternalFailure =
    sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;
using InvalidArgument =
    sdbusplus::xyz::openbmc_project::Common::Error::InvalidArgument;

using UnsupportedRequest =
    sdbusplus::xyz::openbmc_project::Common::Error::UnsupportedRequest;
using NotAllowed = sdbusplus::xyz::openbmc_project::Common::Error::NotAllowed;

struct BmcPairingManagerObject : Ifaces
{
    net::io_context& ioContext;
    std::shared_ptr<sdbusplus::asio::connection> conn;
    enum class ConnectionDirection
    {
        incoming = 0,
        outgoing
    };

    std::array<PeerConnectionStatus, 2> trustedConnectionState{
        PeerConnectionStatus::NotDetermined,
        PeerConnectionStatus::NotDetermined};
    PicController picController;
    using PROVISIONING_HANDLER = std::function<void(const std::string&)>;
    PROVISIONING_HANDLER provisionHandler;

    static constexpr auto busName = "xyz.openbmc_project.BmcPairingManager";
    static constexpr auto objPath = Provisioning::instance_path;
    static constexpr auto interface = Provisioning::interface;

    BmcPairingManagerObject() = delete;
    ~BmcPairingManagerObject() = default;
    BmcPairingManagerObject(const BmcPairingManagerObject&) = delete;
    BmcPairingManagerObject& operator=(const BmcPairingManagerObject&) = delete;
    BmcPairingManagerObject(BmcPairingManagerObject&&) = delete;
    BmcPairingManagerObject& operator=(BmcPairingManagerObject&&) = delete;
    BmcPairingManagerObject(net::io_context& ctx,
                            std::shared_ptr<sdbusplus::asio::connection> conn) :
        Ifaces(*conn, objPath, Ifaces::action::defer_emit), ioContext(ctx),
        conn(conn), picController() // Use default I2C parameters
    {
        // Initialize PicController asynchronously
        net::co_spawn(ctx, initializePicController(), net::detached);
    }

    /**
     * @brief Initialize PicController and load state from I2C
     */
    net::awaitable<void> initializePicController()
    {
        bool success = co_await picController.initialize();
        if (success)
        {
            LOG_INFO("PicController initialized successfully");
            // Update D-Bus property with loaded state
            Ifaces::provisioned(picController.getState(), false);
        }
        else
        {
            LOG_WARNING(
                "PicController initialization failed, using default state");
        }
    }
    void provisionPeer(std::string deviceId) override
    {
        if (deviceId == "self")
        {
            // Spawn async task to set provisioned state
            net::co_spawn(ioContext, setProvisioned(true), net::detached);
            return;
        }
        if (!provisioned())
        {
            LOG_ERROR("This BMC is not provisioned");
            throw NotAllowed();
        }
        provisionHandler(deviceId);
    }
    void setProvisionHandler(PROVISIONING_HANDLER handler)
    {
        provisionHandler = std::move(handler);
    }
    PeerConnectionStatus peerConnected() const override
    {
        auto state = getHighestTrustedConnectionState();
        LOG_DEBUG("PeerConnected state {}",
                  convertPeerConnectionStatusToString(state));
        return state;
    }
    PeerConnectionStatus peerConnected(ConnectionDirection dir)
    {
        return trustedConnectionState[static_cast<size_t>(dir)];
    }
    bool provisioned() const override
    {
        return picController.getState();
    }
    void setPeerConnected(PeerConnectionStatus value, ConnectionDirection dir)
    {
        LOG_DEBUG("Setting PeerConnected state {}",
                  convertPeerConnectionStatusToString(value));
        trustedConnectionState[static_cast<size_t>(dir)] = value;
        Ifaces::peerConnected(getHighestTrustedConnectionState(), false);
    }
    net::awaitable<void> setProvisioned(bool value)
    {
        LOG_DEBUG("Setting Provisioned state {}", value);
        bool success = co_await picController.setState(value);
        if (success)
        {
            LOG_INFO("Successfully set provisioned state to {} via I2C", value);
        }
        else
        {
            LOG_WARNING("Failed to set provisioned state to {} via I2C", value);
        }
        // Update D-Bus property with actual state from picController
        Ifaces::provisioned(picController.getState(), false);
    }

  private:
    /**
     * @brief Determines the highest value in trustedConnectionState entries
     * @return The highest PeerConnectionStatus value from the array
     */
    PeerConnectionStatus getHighestTrustedConnectionState() const
    {
        auto incomingState = trustedConnectionState[static_cast<size_t>(
            ConnectionDirection::incoming)];
        auto outgoingState = trustedConnectionState[static_cast<size_t>(
            ConnectionDirection::outgoing)];
#if 0
        LOG_DEBUG("Incoming connection state: {}",
                  convertPeerConnectionStatusToString(incomingState));
        LOG_DEBUG("Outgoing connection state: {}",
                  convertPeerConnectionStatusToString(outgoingState));
#endif
        auto highestState = maxStatus(incomingState, outgoingState);
        LOG_DEBUG("Highest connection state: {}",
                  convertPeerConnectionStatusToString(highestState));

        return highestState;
    }
    PeerConnectionStatus maxStatus(PeerConnectionStatus first,
                                   PeerConnectionStatus second) const
    {
        if (first == PeerConnectionStatus::Connected ||
            second == PeerConnectionStatus::Connected)
        {
            return PeerConnectionStatus::Connected;
        }
        if (first == PeerConnectionStatus::InProgress ||
            second == PeerConnectionStatus::InProgress)
        {
            return PeerConnectionStatus::InProgress;
        }
        if (first == PeerConnectionStatus::NotConnected ||
            second == PeerConnectionStatus::NotConnected)
        {
            return PeerConnectionStatus::NotConnected;
        }
        return PeerConnectionStatus::NotDetermined;
    }
};
