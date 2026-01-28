#pragma once
#include "logger.hpp"

#include <unistd.h>

#include <filesystem>
constexpr auto CA_PATH_X = "{}etc/ssl/certs/authority/ca.pem";
constexpr auto SELF_CA_PATH_X = "{}etc/ssl/certs/self_ca.pem";
constexpr auto SERVER_PKEY_PATH_X = "{}etc/ssl/private/server_pkey.pem";
constexpr auto ENTITY_SERVER_CERT_PATH_X =
    "{}etc/ssl/certs/https/server_cert.pem";
constexpr auto CLIENT_PKEY_PATH_X = "{}etc/ssl/private/client_pkey.pem";
constexpr auto ENTITY_CLIENT_CERT_PATH_X =
    "{}etc/ssl/certs/https/client_cert.pem";
constexpr auto ENTITY_SERVER_COMBINED_PATH_X =
    "{}etc/ssl/certs/https/server.pem";
constexpr auto ENTITY_CLIENT_COMBINED_PATH_X =
    "{}etc/ssl/certs/https/client.pem";
extern std::string prefix;
inline std::string getPrefix()
{
    return prefix.empty() ? std::format("/tmp/{}/", ::getpid()) : prefix;
}
inline std::string SELF_CA_PATH()
{
    return std::format(SELF_CA_PATH_X, getPrefix());
}
inline std::string CA_PATH()
{
    return std::format(CA_PATH_X, getPrefix());
}
inline std::string SERVER_PKEY_PATH()
{
    return std::format(SERVER_PKEY_PATH_X, getPrefix());
}
inline std::string ENTITY_SERVER_CERT_PATH()
{
    return std::format(ENTITY_SERVER_CERT_PATH_X, getPrefix());
}
inline std::string CLIENT_PKEY_PATH()
{
    return std::format(CLIENT_PKEY_PATH_X, getPrefix());
}
inline std::string ENTITY_CLIENT_CERT_PATH()
{
    return std::format(ENTITY_CLIENT_CERT_PATH_X, getPrefix());
}
inline std::string ENTITY_SERVER_COMBINED_PATH()
{
    return std::format(ENTITY_SERVER_COMBINED_PATH_X, getPrefix());
}
inline std::string ENTITY_CLIENT_COMBINED_PATH()
{
    return std::format(ENTITY_CLIENT_COMBINED_PATH_X, getPrefix());
}

inline void createCertDirectories()
{
    if (std::filesystem::exists(
            std::filesystem::path(CA_PATH()).parent_path()) &&
        std::filesystem::exists(
            std::filesystem::path(SERVER_PKEY_PATH()).parent_path()) &&
        std::filesystem::exists(
            std::filesystem::path(ENTITY_SERVER_CERT_PATH()).parent_path()))
    {
        LOG_DEBUG("Directories already exist, skipping creation");
        return;
    }
    LOG_DEBUG("Creating directories for certificates at {}, {}, {}", CA_PATH(),
              SERVER_PKEY_PATH(), ENTITY_SERVER_CERT_PATH());
    std::filesystem::create_directories(
        std::filesystem::path(CA_PATH()).parent_path());
    std::filesystem::create_directories(
        std::filesystem::path(SERVER_PKEY_PATH()).parent_path());
    std::filesystem::create_directories(
        std::filesystem::path(ENTITY_SERVER_CERT_PATH()).parent_path());
}
inline void clearCertificates()
{
    if (std::filesystem::exists(std::filesystem::path(CA_PATH())))
    {
        std::filesystem::remove(std::filesystem::path(CA_PATH()));
    }
    if (std::filesystem::exists(std::filesystem::path(SERVER_PKEY_PATH())))
    {
        std::filesystem::remove(std::filesystem::path(SERVER_PKEY_PATH()));
    }
    if (std::filesystem::exists(
            std::filesystem::path(ENTITY_SERVER_CERT_PATH())))
    {
        std::filesystem::remove(
            std::filesystem::path(ENTITY_SERVER_CERT_PATH()));
    }
    if (std::filesystem::exists(std::filesystem::path(CLIENT_PKEY_PATH())))
    {
        std::filesystem::remove(std::filesystem::path(CLIENT_PKEY_PATH()));
    }
    if (std::filesystem::exists(
            std::filesystem::path(ENTITY_CLIENT_CERT_PATH())))
    {
        std::filesystem::remove(
            std::filesystem::path(ENTITY_CLIENT_CERT_PATH()));
    }
}
