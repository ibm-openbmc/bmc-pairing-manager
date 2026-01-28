#pragma once
#include "cert_generator.hpp"

using namespace NSNAME;
constexpr auto CLIENT_PKEY_NAME = "/etc/ssl/private/client.mtls.key";
constexpr auto ENTITY_CLIENT_CERT_NAME = "/etc/ssl/certs/https/client.mtls.pem";
constexpr auto ENTITY_CLIENT_COMBINED_NAME =
    "/etc/ssl/certs/https/client.mtls.combined.pem";
constexpr auto SERVER_PKEY_NAME = "/etc/ssl/private/server.mtls.key";
constexpr auto ENTITY_SERVER_CERT_NAME = "/etc/ssl/certs/https/server.mtls.pem";
constexpr auto ENTITY_SERVER_COMBINED_NAME =
    "/etc/ssl/certs/https/server.mtls.combined.pem";
constexpr auto CA_CERT_NAME = "/etc/ssl/certs/bmc.ca.pem";
constexpr auto CA_KEY_NAME = "/etc/ssl/private/bmc.ca.key";
constexpr auto SIGNING_CERT_NAME = "/etc/ssl/certs/https/signing.pem";
constexpr auto SIGNING_KEY_NAME = "/etc/ssl/private/signing.key";
constexpr auto SIGNING_COMBINED_NAME =
    "/etc/ssl/certs/https/signing.combined.pem";

bool processInterMediateCA(const openssl_ptr<EVP_PKEY, EVP_PKEY_free>& pkey,
                           const openssl_ptr<X509, X509_free>& ca)
{
    if (!pkey)
    {
        LOG_ERROR("Failed to read private key from provided data");
        return false;
    }
    if (!ca)
    {
        LOG_ERROR("Failed to read CA certificate from provided data");
        return false;
    }
    std::array<ENTITY_DATA, 3> entity_data = {
        ENTITY_DATA{"clientAuth", std::format(CLIENT_PKEY_NAME),
                    std::format(ENTITY_CLIENT_CERT_NAME),
                    std::format(ENTITY_CLIENT_COMBINED_NAME)},
        ENTITY_DATA{"serverAuth", std::format(SERVER_PKEY_NAME),
                    std::format(ENTITY_SERVER_CERT_NAME),
                    std::format(ENTITY_SERVER_COMBINED_NAME)},
        ENTITY_DATA{"signing", std::format(SIGNING_KEY_NAME),
                    std::format(SIGNING_CERT_NAME),
                    std::format(SIGNING_COMBINED_NAME)}};
    auto certsdata = createAndSaveEntityCertificate<3>(pkey, ca, "BMC Entity",
                                                       entity_data, 1);
    if (!certsdata)
    {
        LOG_ERROR("Failed to create server entity certificate");
        return false;
    }
    auto [serverCert, serverKey] = std::move(*certsdata);

    // auto serverCert = loadCertificate(ENTITY_SERVER_CERT_NAME);
    if (!isSignedByCA(serverCert, getPublicKeyFromCert(ca)))
    {
        LOG_ERROR("Failed to verify signature of server certificate");
    }
    auto clientCertsdata = createAndSaveEntityCertificate<3>(
        pkey, ca, "BMC Entity", entity_data, 0);
    if (!clientCertsdata)
    {
        LOG_ERROR("Failed to create client entity certificate");
        return false;
    }
    auto signCertData = createAndSaveEntityCertificate<3>(
        pkey, ca, "BMC Entity", entity_data, 2);
    if (!signCertData)
    {
        LOG_ERROR("Failed to create signing certificate");
        return false;
    }
    auto [clientCert, clientKey] = std::move(*clientCertsdata);

    // auto clientCert = loadCertificate(ENTITY_CLIENT_CERT_NAME);
    if (!isSignedByCA(clientCert, getPublicKeyFromCert(ca)))
    {
        LOG_ERROR("Failed to verify signature of  client certificate");
    }

    return true;
}
bool ensureCertificates(const std::string& verify_cert, bool selfsigned)
{
    if (std::filesystem::exists(verify_cert))
    {
        LOG_DEBUG("Certificate file {} does exist", verify_cert);
        return true;
    }
    if (selfsigned)
    {
        auto [ca, pkey] = create_ca_cert(nullptr, nullptr, "BMC CA");
        if (!ca || !pkey)
        {
            throw std::runtime_error(
                "Failed to create CA certificate and private key");
        }
        if (!processInterMediateCA(pkey, ca))
        {
            throw std::runtime_error("Failed to create entity certificates");
        }
        saveCertificate(CA_CERT_NAME, ca, true);
        savePrivateKey(CA_KEY_NAME, pkey, true);
    }
    return selfsigned;
}
