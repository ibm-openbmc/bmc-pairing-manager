#pragma once
/**
 * @file spdm_measurement.hpp
 * @brief Fetches signed SPDM measurements from the responder(s) exposed by
 *        spdmd over D-Bus (xyz.openbmc_project.Attestation.MeasurementSet).
 *
 * To be used by SpdmAttestationStrategy (spdm_attestation.hpp).
 */
#include "beastdefs.hpp"
#include "logger.hpp"
#include "sdbus_calls.hpp"

#include <xyz/openbmc_project/Attestation/MeasurementSet/common.hpp>

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace NSNAME
{
namespace spdm_measurement
{
using MeasurementSetCommon =
    sdbusplus::common::xyz::openbmc_project::attestation::MeasurementSet;

/// SPDM measurement indices requested from the responder. Index 0 is the
/// "total count" sentinel and must not be mixed with specific indices.
constexpr std::array<size_t, 4> defaultIndices{1, 2, 3, 4};

/// SPDM slot 0: platform certificate exchange.
constexpr size_t platformCertSlot = 0;
/// SPDM slot 1: SPDM certificate and measurements. Signed measurements are
/// requested on this slot.
constexpr size_t measurementSlot = 1;

/** Reply of SPDMGetSignedMeasurements. */
struct SignedMeasurements
{
    sdbuscompat::object_path certPath;
    std::string hashAlgo;    ///< e.g. "SHA256", "SHA384"
    std::string certPem;     ///< responder certificate (PEM)
    std::string measurement; ///< base64 of the measurement blocks + signature
    std::string signAlgo;    ///< e.g. "ECDSA_P256"
    std::string version;
    std::vector<uint8_t> opaqueData; ///< TPM quote frames, may be empty
};

/**
 * Call SPDMGetSignedMeasurements for @p slotId on one MeasurementSet object.
 *
 * The nonce is sent empty. spdmd ignores it and requests no signature, so
 * libspdm creates no nonce for this call. The interface documents a 32-byte
 * hex value; revisit this when spdmd signs the request.
 *
 * @return the reply, or std::nullopt if the D-Bus call failed.
 */
inline net::awaitable<std::optional<SignedMeasurements>> getSignedMeasurements(
    std::shared_ptr<sdbusplus::asio::connection> conn, std::string service,
    std::string objPath, size_t slotId, std::span<const size_t> indices)
{
    std::string nonce{};
    auto [ec, certPath, hashAlgo, certPem, measurement, signAlgo, version,
          opaqueData] =
        co_await awaitable_dbus_method_call<
            sdbuscompat::object_path, std::string, std::string, std::string,
            std::string, std::string, std::vector<uint8_t>>(
            *conn, service, objPath, MeasurementSetCommon::interface,
            MeasurementSetCommon::method_names::spdm_get_signed_measurements,
            std::vector<size_t>(indices.begin(), indices.end()), nonce,
            slotId);
    if (ec)
    {
        LOG_ERROR("[slot={}] SPDMGetSignedMeasurements on {} failed: {}",
                  slotId, objPath, ec.message());
        co_return std::nullopt;
    }

    LOG_INFO("[slot={}] version={} hashAlgo={} signAlgo={} opaque={} bytes",
             slotId, version, hashAlgo, signAlgo, opaqueData.size());
    co_return SignedMeasurements{
        std::move(certPath),    std::move(hashAlgo), std::move(certPem),
        std::move(measurement), std::move(signAlgo), std::move(version),
        std::move(opaqueData)};
}

/** Find every object implementing the MeasurementSet interface. */
inline net::awaitable<SubTreeMap> findMeasurementSets(
    std::shared_ptr<sdbusplus::asio::connection> conn)
{
    auto [ec, subtree] = co_await getSubTree(
        *conn, "/", 0, {std::string(MeasurementSetCommon::interface)});
    if (ec)
    {
        LOG_WARNING("GetSubTree for MeasurementSet failed: {}", ec.message());
        co_return SubTreeMap{};
    }
    co_return subtree;
}

/**
 * True if the reply carries a certificate. spdmd returns a non-empty PEM on
 * success and an empty PEM on any failure, so this is the success check for
 * both slots.
 */
inline bool hasCertificate(const SignedMeasurements& reply)
{
    return !reply.certPem.empty();
}

/**
 * Validate the platform certificate of one responder (SPDM slot 0).
 *
 * spdmd fetches the certificate chain, and runs CHALLENGE_AUTH when the slot
 * is CHALLENGE_USE, before it replies. On any failure it replies with empty
 * fields. A D-Bus error is also a failure.
 *
 * spdmd does not reject a chain that fails the trust anchor check, because
 * libspdm reports that as a warning (VERIF_NO_AUTHORITY). This check cannot
 * see that case.
 *
 * @return true if spdmd returned a certificate. Otherwise logs
 *         AttestationFailed and returns false.
 */
inline net::awaitable<bool> validatePlatformCertificate(
    std::shared_ptr<sdbusplus::asio::connection> conn, std::string service,
    std::string objPath)
{
    auto reply = co_await getSignedMeasurements(
        conn, service, objPath, platformCertSlot, defaultIndices);
    if (!reply || !hasCertificate(*reply))
    {
        LOG_ERROR("AttestationFailed: slot 0 certificate not validated: {}",
                  objPath);
        co_return false;
    }
    co_return true;
}

/**
 * Get the signed measurement (SPDM slot 1) of one responder.
 *
 * The platform certificate is validated first. If that fails, processing
 * stops and slot 1 is not requested. Slot 1 must return a certificate and a
 * non-empty measurement.
 *
 * @return the slot 1 reply, or std::nullopt if processing stopped.
 */
inline net::awaitable<std::optional<SignedMeasurements>> getMeasurement(
    std::shared_ptr<sdbusplus::asio::connection> conn, std::string service,
    std::string objPath)
{
    if (!co_await validatePlatformCertificate(conn, service, objPath))
    {
        co_return std::nullopt;
    }

    auto reply = co_await getSignedMeasurements(
        conn, service, objPath, measurementSlot, defaultIndices);
    if (!reply || !hasCertificate(*reply) || reply->measurement.empty())
    {
        LOG_ERROR("MeasurementFailed: slot 1 measurement not returned: {}",
                  objPath);
        co_return std::nullopt;
    }
    co_return reply;
}
} // namespace spdm_measurement
} // namespace NSNAME
