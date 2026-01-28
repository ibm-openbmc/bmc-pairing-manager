#pragma once
#include "cert_generator.hpp"
#include "eventmethods.hpp"
#include "eventqueue.hpp"
#include "globaldefs.hpp"

#include <openssl/x509.h>

#include <iomanip>
#include <sstream>
using namespace NSNAME;
constexpr auto INSTALL_CERTIFICATES = "InstallCertificates";
constexpr auto INSTALL_CERTIFICATES_RESP = "InstallCertificatesResp";
using ENTITY_DATA =
    std::tuple<const char*, std::string, std::string, std::string>;

// Helper function to create certificate hash file for trust store
inline bool createCertificateHashFile(const X509Ptr& cert,
                                      const std::string& certPath)
{
    if (!cert)
    {
        LOG_ERROR("Certificate pointer is null");
        return false;
    }

    // Calculate the certificate hash using X509_subject_name_hash
    unsigned long hash = X509_subject_name_hash(cert.get());

    // Get the directory path where the certificate is stored
    std::filesystem::path certFilePath(certPath);
    std::filesystem::path certDir = certFilePath.parent_path();

    // Format hash as 8-digit hex string
    std::ostringstream hashStream;
    hashStream << std::hex << std::setw(8) << std::setfill('0') << hash;
    std::string hashStr = hashStream.str();

    // Find the next available index for this hash (handle collisions)
    int index = 0;
    std::filesystem::path hashFilePath;
    do
    {
        hashFilePath = certDir / (hashStr + "." + std::to_string(index));
        index++;
    } while (std::filesystem::exists(hashFilePath) && index < 100);

    if (index >= 100)
    {
        LOG_ERROR("Too many hash collisions for certificate hash {}", hashStr);
        return false;
    }

    // Create symlink from hash file to actual certificate
    std::error_code ec;
    std::filesystem::create_symlink(certFilePath.filename(), hashFilePath, ec);
    if (ec)
    {
        LOG_ERROR("Failed to create hash symlink {} -> {}: {}",
                  hashFilePath.string(), certFilePath.string(), ec.message());
        return false;
    }

    LOG_DEBUG("Created certificate hash file: {} -> {}", hashFilePath.string(),
              certFilePath.string());
    return true;
}

// Helper function to verify trust store directory is usable
inline bool verifyTrustStorePath(const std::string& dirPath)
{
    namespace fs = std::filesystem;

    if (!fs::exists(dirPath))
    {
        LOG_ERROR("Trust store directory does not exist: {}", dirPath);
        return false;
    }

    if (!fs::is_directory(dirPath))
    {
        LOG_ERROR("Trust store path is not a directory: {}", dirPath);
        return false;
    }

    // Check if directory is readable
    std::error_code ec;
    auto perms = fs::status(dirPath, ec).permissions();
    if (ec)
    {
        LOG_ERROR("Failed to get permissions for {}: {}", dirPath,
                  ec.message());
        return false;
    }

    // Check for read and execute permissions (needed to access directory)
    if ((perms & fs::perms::owner_read) == fs::perms::none ||
        (perms & fs::perms::owner_exec) == fs::perms::none)
    {
        LOG_ERROR("Insufficient permissions for trust store directory: {}",
                  dirPath);
        return false;
    }

    LOG_DEBUG("Trust store directory verified: {}", dirPath);
    return true;
}

// Helper function to save combined certificate and private key to a single file
inline bool saveCombinedCertAndKey(const X509Ptr& cert, const EVP_PKEYPtr& key,
                                   const std::string& filename)
{
    openssl_ptr<BIO, BIO_free_all> combined_bio(BIO_new(BIO_s_mem()),
                                                BIO_free_all);

    // Write certificate to BIO
    if (!PEM_write_bio_X509(combined_bio.get(), cert.get()))
    {
        LOG_ERROR("Failed to write certificate to combined BIO");
        return false;
    }

    // Write private key to BIO
    if (!PEM_write_bio_PrivateKey(combined_bio.get(), key.get(), nullptr,
                                  nullptr, 0, nullptr, nullptr))
    {
        LOG_ERROR("Failed to write private key to combined BIO");
        return false;
    }

    if (!saveBio(filename, std::move(combined_bio)))
    {
        LOG_ERROR("Failed to save combined certificate and key to {}",
                  filename);
        return false;
    }

    LOG_DEBUG("Combined certificate and private key saved to {}", filename);
    return true;
}

template <int COUNT>
std::optional<std::pair<X509Ptr, EVP_PKEYPtr>> createAndSaveEntityCertificate(
    const EVP_PKEYPtr& ca_pkey, const X509Ptr& ca,
    const std::string& common_name,
    const std::array<ENTITY_DATA, COUNT>& entity_data, int index)
{
    auto ca_name = openssl_ptr<X509_NAME, X509_NAME_free>(
        X509_NAME_dup(X509_get_subject_name(ca.get())), X509_NAME_free);
    auto [cert,
          key] = create_leaf_cert(ca_pkey.get(), ca_name.get(), common_name);
    if (!cert || !key)
    {
        LOG_ERROR("Failed to create entity certificate");
        return std::nullopt;
    }

    // Add serverAuth extended key usage
    // openssl_ptr<X509_EXTENSION, X509_EXTENSION_free> ext(
    //     X509V3_EXT_conf_nid(nullptr, nullptr, NID_ext_key_usage,
    //                         (char*)std::get<0>(entity_data[server])),
    //     X509_EXTENSION_free);
    // if (!ext)
    // {
    //     LOG_ERROR("Failed to add serverAuth extension");
    //     return std::nullopt;
    // }
    // X509_add_ext(cert.get(), ext.get(), -1);
    if (!savePrivateKey(std::get<1>(entity_data[index]), key))
    {
        LOG_ERROR("Failed to save private key to {}",
                  std::get<1>(entity_data[index]));
        return std::nullopt;
    }
    std::vector<X509*> cert_chain;
    cert_chain.emplace_back(cert.get());
    cert_chain.emplace_back(ca.get());
    std::string filename = std::get<2>(entity_data[index]);
    if (!saveCertificate(filename, cert_chain))
    {
        LOG_ERROR("Failed to save entity certificate to {}",
                  std::get<2>(entity_data[index]));
        return std::nullopt;
    }

    // Save combined certificate and private key file
    std::string combined_filename = std::get<3>(entity_data[index]);
    if (!saveCombinedCertAndKey(cert, key, combined_filename))
    {
        LOG_ERROR("Failed to save combined certificate and key to {}",
                  combined_filename);
        return std::nullopt;
    }

    LOG_DEBUG("Entity certificate and private key saved to {} and {}, "
              "combined file saved to {}",
              std::get<2>(entity_data[index]), std::get<1>(entity_data[index]),
              combined_filename);
    return std::make_optional(std::make_pair(std::move(cert), std::move(key)));
}
struct CertificateExchanger
{
    EventQueue& eventQueue;
    net::io_context& ioContext;
    X509Ptr mCaCert{nullptr, X509_free};
    CertificateExchanger(EventQueue& eventQueue, net::io_context& ioContext) :
        eventQueue(eventQueue), ioContext(ioContext)
    {
        mCaCert = createCertificates();
    }
    CertificateExchanger(const CertificateExchanger&) = delete;
    CertificateExchanger& operator=(const CertificateExchanger&) = delete;

    net::awaitable<bool> exchange(Streamer streamer)
    {
        createCertDirectories();
        LOG_DEBUG("Exchanging certificates");
        if (!co_await sendCertificate(streamer))
        {
            LOG_ERROR("Failed to send certificates");
            co_return false;
        }
        if (!co_await recieveCertificate(streamer))
        {
            LOG_ERROR("Failed to receive certificate");
            co_return false;
        }
        LOG_DEBUG("Certificate exchange completed successfully");
        co_return true;
    }
    net::awaitable<bool> waitForExchange(Streamer streamer)
    {
        createCertDirectories();
        if (!co_await recieveCertificate(streamer))
        {
            LOG_ERROR("Failed to receive certificate");
            co_return false;
        }
        if (!co_await sendCertificate(streamer))
        {
            LOG_ERROR("Failed to send certificate");
            co_return false;
        }
        co_return true;
    }

    static bool processInterMediateCA(
        const openssl_ptr<EVP_PKEY, EVP_PKEY_free>& pkey,
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
        std::array<ENTITY_DATA, 2> entity_data = {
            ENTITY_DATA{"clientAuth", CLIENT_PKEY_PATH(),
                        ENTITY_CLIENT_CERT_PATH(),
                        ENTITY_CLIENT_COMBINED_PATH()},
            ENTITY_DATA{"serverAuth", SERVER_PKEY_PATH(),
                        ENTITY_SERVER_CERT_PATH(),
                        ENTITY_SERVER_COMBINED_PATH()}};
        auto caname = openssl_ptr<X509_NAME, X509_NAME_free>(
            X509_NAME_dup(X509_get_subject_name(ca.get())), X509_NAME_free);
        auto servCert = createAndSaveEntityCertificate<2>(
            pkey, ca, "BMC Entity", entity_data, 1);
        if (!servCert)
        {
            LOG_ERROR("Failed to create server entity certificate");
            return false;
        }
        auto clientCert = createAndSaveEntityCertificate<2>(pkey, ca, "service",
                                                            entity_data, 0);
        if (!clientCert)
        {
            LOG_ERROR("Failed to create client entity certificate");
            return false;
        }
        return true;
    }
    bool installCertificates(const std::string& castr)
    {
        openssl_ptr<X509, X509_free> ca(
            PEM_read_bio_X509(BIO_new_mem_buf(castr.data(), castr.size()),
                              nullptr, nullptr, nullptr),
            X509_free);

        if (!saveCertificate(CA_PATH(), ca))
        {
            LOG_ERROR("Failed to save CA certificate to {}", CA_PATH());
            return false;
        }
        LOG_DEBUG("CA Certificates written to {} ", CA_PATH());

        // Create certificate hash file for trust store usage
        if (!createCertificateHashFile(ca, CA_PATH()))
        {
            LOG_ERROR("Failed to create certificate hash file for {}",
                      CA_PATH());
            return false;
        }

        // Verify that the directory can be used as a trust store path
        std::filesystem::path caPath(CA_PATH());
        std::string trustStoreDir = caPath.parent_path().string();
        if (!verifyTrustStorePath(trustStoreDir))
        {
            LOG_ERROR("Trust store directory verification failed: {}",
                      trustStoreDir);
            return false;
        }

        LOG_DEBUG(
            "Certificate hash file created and trust store verified for {}",
            trustStoreDir);
        return true;
    }
    static X509Ptr createCertificates()
    {
        if (fs::exists(SELF_CA_PATH()))
        {
            return loadCertificate(SELF_CA_PATH());
        }
        auto [ca_cert, ca_pkey] = create_ca_cert(nullptr, nullptr, "BMC CA");
        if (!ca_cert || !ca_pkey)
        {
            LOG_ERROR("Failed to create CA certificate and private key");
            return makeX509Ptr(nullptr);
        }
        if (!processInterMediateCA(ca_pkey, ca_cert))
        {
            LOG_ERROR("Failed to process intermediate CA");
            return makeX509Ptr(nullptr);
        }
        if (!saveCertificate(SELF_CA_PATH(), ca_cert))
        {
            LOG_ERROR("Failed to save entity certificate to {}",
                      SELF_CA_PATH());
            return makeX509Ptr(nullptr);
        }
        return ca_cert;
    }
    net::awaitable<bool> sendCertificate(Streamer streamer)
    {
        if (!mCaCert)
        {
            mCaCert = createCertificates();
        }
        if (!mCaCert)
        {
            co_return false;
        }
        std::string intermediate_ca =
            toString(mCaCert); // Convert to string for sending

        nlohmann::json jsonBody;
        jsonBody["CA"] = intermediate_ca;
        auto [ec, size] = co_await sendHeader(
            streamer, makeEvent(INSTALL_CERTIFICATES, jsonBody.dump()));
        if (ec)
        {
            LOG_ERROR("Failed to send INSTALL_CERTIFICATES event: {}",
                      ec.message());
            co_return false;
        }
        if (!co_await recieveCertificateStatus(streamer))
        {
            LOG_ERROR("Failed to Install certificates");
            co_return false;
        }
        LOG_DEBUG("Certificates installed successfully");
        co_return true;
    }
    net::awaitable<bool> recieveCertificateStatus(Streamer streamer)
    {
        auto [ec, event] = co_await readHeader(streamer);
        if (ec)
        {
            LOG_ERROR("Failed to read response: {}", ec.message());
            co_return false;
        }
        auto [id, body] = parseEvent(event);
        if (id == INSTALL_CERTIFICATES_RESP)
        {
            auto jsonBody = nlohmann::json::parse(body);
            auto installed = jsonBody["status"].get<bool>();
            if (!installed)
            {
                LOG_ERROR("Failed to install certificates");
                co_return false;
            }
            LOG_DEBUG("Certificates installed successfully");
            co_return true;
        }

        LOG_ERROR("Unexpected event ID: {}", id);
        co_return false;
    }
    net::awaitable<bool> sendInstallStatus(Streamer& streamer, bool status)
    {
        nlohmann::json jsonBody;
        jsonBody["status"] = status;
        auto [ec, size] = co_await sendHeader(
            streamer, makeEvent(INSTALL_CERTIFICATES_RESP, jsonBody.dump()));
        if (ec)
        {
            LOG_ERROR("Failed to send INSTALL_CERTIFICATES_RESP event: {}",
                      ec.message());
            co_return false;
        }
        co_return status;
    }
    net::awaitable<bool> recieveCertificate(Streamer streamer)
    {
        auto [ec, event] = co_await readHeader(streamer);
        if (ec)
        {
            LOG_ERROR("Failed to read response: {}", ec.message());
            co_return false;
        }
        auto [id, body] = parseEvent(event);
        if (id == INSTALL_CERTIFICATES)
        {
            auto jsonBody = nlohmann::json::parse(body);
            auto CA = jsonBody["CA"].get<std::string>();
            if (CA.empty())
            {
                LOG_ERROR("CA or PKEY is empty in the event body");
                co_return co_await sendInstallStatus(streamer, false);
            }
            if (!installCertificates(CA))
            {
                LOG_ERROR("Failed to install certificates");
                co_return co_await sendInstallStatus(streamer, false);
            }
            co_return co_await sendInstallStatus(streamer, true);
        }
        LOG_ERROR("Unexpected event ID: {}", id);
        co_return false;
    }
};
