#pragma once
#include "beastdefs.hpp"
#include "dbusproperty_watcher.hpp"
#include "logger.hpp"
#include "sdbus_calls.hpp"
#include "spdm_measurement.hpp"

#include <memory>
#include <string>

namespace NSNAME
{
/**
 * Strategy that performs attestation by calling SPDM directly.
 *
 * attest() validates the platform certificate (SPDM slot 0) and then gets the
 * measurement (SPDM slot 1) of every MeasurementSet responder. The
 * measurements are not validated yet.
 */
struct SpdmAttestationStrategy
{
    static net::awaitable<bool> attest(
        std::shared_ptr<sdbusplus::asio::connection> conn,
        [[maybe_unused]] std::string deviceName)
    {
        auto subtree = co_await spdm_measurement::findMeasurementSets(conn);
        if (subtree.empty())
        {
            LOG_ERROR("No MeasurementSet responders found");
            co_return false;
        }

        for (const auto& [objPath, serviceMap] : subtree)
        {
            if (serviceMap.empty())
            {
                LOG_ERROR("No owning service for {}", objPath);
                co_return false;
            }
            auto measurement = co_await spdm_measurement::getMeasurement(
                conn, serviceMap.begin()->first, objPath);
            if (!measurement)
            {
                co_return false;
            }
        }
        co_return true;
    }

    static void watchAttestationState(
        [[maybe_unused]] net::io_context& ioc,
        [[maybe_unused]] const std::shared_ptr<sdbusplus::asio::connection>&
            conn,
        [[maybe_unused]] WatchHandler<bool> auto handler)
    {
        LOG_ERROR("SPDM attestation state watcher is not implemented");
    }
};
} // namespace NSNAME
