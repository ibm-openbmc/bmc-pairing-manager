#pragma once
#include <boost/asio.hpp>

#include <filesystem>
#include <format>
#include <string>
using namespace reactor;
namespace fs = std::filesystem;
inline std::string trustStorePath()
{
    return "/etc/ssl/certs/authority";
}
inline std::string ENTITY_CLIENT_CERT_PATH()
{
    return "/etc/ssl/certs/https/client_cert.pem";
}
inline std::string CLIENT_PKEY_PATH()
{
    return "/etc/ssl/private/client_pkey.pem";
}
inline std::string ENTITY_SERVER_CERT_PATH()
{
    return "/etc/ssl/certs/https/server_cert.pem";
}
inline std::string SERVER_PKEY_PATH()
{
    return "/etc/ssl/private/server_pkey.pem";
}
std::optional<ssl::context> getClientContext()
{
    if (fs::exists(ENTITY_CLIENT_CERT_PATH()) &&
        fs::exists(CLIENT_PKEY_PATH()) && fs::exists(trustStorePath()))
    {
        boost::asio::ssl::context ssl_context(
            boost::asio::ssl::context::tls_client);

        // Configure the context for modern, secure operation
        ssl_context.set_options(
            boost::asio::ssl::context::default_workarounds |
            boost::asio::ssl::context::no_sslv2 |
            boost::asio::ssl::context::no_sslv3 |
            boost::asio::ssl::context::no_tlsv1 |
            boost::asio::ssl::context::no_tlsv1_1);

        // Set the ciphers to only use secure, modern ones
        // This should be compatible with the server's cipher list
        SSL_CTX_set_cipher_list(
            ssl_context.native_handle(),
            "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256");

        ssl_context.add_verify_path(trustStorePath());
        ssl_context.set_verify_mode(boost::asio::ssl::verify_peer);
        ssl_context.use_certificate_chain_file(ENTITY_CLIENT_CERT_PATH());
        ssl_context.use_private_key_file(CLIENT_PKEY_PATH(),
                                         boost::asio::ssl::context::pem);
        return std::optional<ssl::context>(std::move(ssl_context));
    }
    LOG_ERROR("Client SSL context files are missing searched paths: {}, {}, {}",
              ENTITY_CLIENT_CERT_PATH(), CLIENT_PKEY_PATH(), trustStorePath());
    return std::nullopt;
}
std::optional<ssl::context> getServerContext()
{
    if (fs::exists(ENTITY_SERVER_CERT_PATH()) &&
        fs::exists(SERVER_PKEY_PATH()) && fs::exists(trustStorePath()))
    {
        // Create a context that supports TLS 1.2 and 1.3
        boost::asio::ssl::context ssl_context(
            boost::asio::ssl::context::tls_server);

        // Configure the context for modern, secure operation
        ssl_context.set_options(
            boost::asio::ssl::context::default_workarounds |
            boost::asio::ssl::context::no_sslv2 |
            boost::asio::ssl::context::no_sslv3 |
            boost::asio::ssl::context::no_tlsv1 |
            boost::asio::ssl::context::no_tlsv1_1 |
            boost::asio::ssl::context::single_dh_use);

        // Set the ciphers to only use secure, modern ones
        // This is an example, you can get a list of modern ciphers from tools
        // like Mozilla SSL Config Generator
        SSL_CTX_set_cipher_list(
            ssl_context.native_handle(),
            "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256");

        ssl_context.use_certificate_chain_file(ENTITY_SERVER_CERT_PATH());
        ssl_context.use_private_key_file(SERVER_PKEY_PATH(),
                                         boost::asio::ssl::context::pem);
        ssl_context.add_verify_path(trustStorePath());
        ssl_context.set_verify_mode(
            boost::asio::ssl::verify_peer |
            boost::asio::ssl::verify_fail_if_no_peer_cert);
        return std::optional(std::move(ssl_context));
    }
    return std::nullopt;
}
