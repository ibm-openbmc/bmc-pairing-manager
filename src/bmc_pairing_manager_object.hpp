#pragma once
#include "logger.hpp"
#include "pic_controller.hpp"
#include "sdbus_calls.hpp"

#include <xyz/openbmc_project/BmcPairing/BmcPairing/server.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

using namespace reactor;

using namespace sdbusplus::server::xyz::openbmc_project::bmc_pairing;
using BmcPairingIface =
    sdbusplus::server::xyz::openbmc_project::bmc_pairing::BmcPairing;
using Ifaces = sdbusplus::server::object_t<BmcPairingIface>;
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
    using PAIRING_HANDLER = std::function<void(const std::string&)>;
    PAIRING_HANDLER pairingHandler;

    static constexpr auto busName = "xyz.openbmc_project.BmcPairing";
    static constexpr auto objPath = BmcPairingIface::instance_path;
    static constexpr auto interface = BmcPairingIface::interface;

    BmcPairingManagerObject() = delete;
    ~BmcPairingManagerObject() override = default;
    BmcPairingManagerObject(const BmcPairingManagerObject&) = delete;
    BmcPairingManagerObject& operator=(const BmcPairingManagerObject&) = delete;
    BmcPairingManagerObject(BmcPairingManagerObject&&) = delete;
    BmcPairingManagerObject& operator=(BmcPairingManagerObject&&) = delete;

    BmcPairingManagerObject(
        net::io_context& ctx,
        const std::shared_ptr<sdbusplus::asio::connection>& conn) :
        Ifaces(*conn, objPath, Ifaces::action::defer_emit), ioContext(ctx),
        conn(conn), picController()
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
            Ifaces::paired(picController.getState(), false);
        }
        else
        {
            LOG_WARNING(
                "PicController initialization failed, using default state");
        }
    }

    /** @brief Implementation for PairPeer — starts pairing on the peer BMC.
     *  Returns an object path implementing xyz.openbmc_project.Common.Progress.
     */
    sdbuscompat::object_path pairPeer(std::string bmcId) override
    {
        if (bmcId == "self")
        {
            // Spawn async task to set paired state
            net::co_spawn(ioContext, setPaired(true), net::detached);
            return {objPath};
        }
        if (!paired())
        {
            LOG_ERROR("This BMC is not paired");
            throw NotAllowed();
        }
        pairingHandler(bmcId);
        return {objPath};
    }

    void setPairingHandler(PAIRING_HANDLER handler)
    {
        pairingHandler = std::move(handler);
    }

    PeerConnectionStatus peerConnected() const override
    {
        auto state = getHighestTrustedConnectionState();
        LOG_DEBUG("PeerConnected state {}",
                  convertPeerConnectionStatusToString(state));
        return state;
    }

    PeerConnectionStatus peerConnected(ConnectionDirection dir) const
    {
        return trustedConnectionState[static_cast<size_t>(dir)];
    }

    bool paired() const override
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

    net::awaitable<void> setPaired(bool value)
    {
        LOG_DEBUG("Setting Paired state {}", value);
        bool success = co_await picController.setState(value);
        if (success)
        {
            LOG_INFO("Successfully set paired state to {} via I2C", value);
        }
        else
        {
            LOG_WARNING("Failed to set paired state to {} via I2C", value);
        }
        // Update D-Bus property with actual state from picController
        Ifaces::paired(picController.getState(), false);
    }

  private:
    /**
     * @brief Returns the highest-priority connection state across both
     *        incoming and outgoing directions.
     */
    PeerConnectionStatus getHighestTrustedConnectionState() const
    {
        auto incomingState = trustedConnectionState[static_cast<size_t>(
            ConnectionDirection::incoming)];
        auto outgoingState = trustedConnectionState[static_cast<size_t>(
            ConnectionDirection::outgoing)];

        auto highestState = maxStatus(incomingState, outgoingState);
        LOG_DEBUG("Highest connection state: {}",
                  convertPeerConnectionStatusToString(highestState));
        return highestState;
    }

    static PeerConnectionStatus maxStatus(PeerConnectionStatus first,
                                          PeerConnectionStatus second)
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
