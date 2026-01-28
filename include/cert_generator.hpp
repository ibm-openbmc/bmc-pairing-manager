#pragma once
#include "logger.hpp"

#include <dlfcn.h>
#include <err.h>
#include <openssl/core.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <openssl/param_build.h>
#include <openssl/pem.h>
#include <openssl/provider.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/store.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <fstream>
#include <iterator>
#include <memory>
#include <string>
#include <vector>
namespace NSNAME
{
// Forward declarations for PEM<->DER private-key string/buffer helpers
bool pemKeyStringToDer(const std::string& pem, std::vector<uint8_t>& der);
bool derKeyToPemString(const std::vector<uint8_t>& der, std::string& pem);

// Helper for unique_ptr with OpenSSL types
template <typename T, void (*Deleter)(T*)>
using openssl_ptr = std::unique_ptr<T, decltype(Deleter)>;
using X509Ptr = openssl_ptr<X509, X509_free>;
using BIOPtr = openssl_ptr<BIO, BIO_free_all>;
X509Ptr makeX509Ptr(X509* ptr)
{
    return X509Ptr(ptr, X509_free);
}
using EVP_PKEYPtr = openssl_ptr<EVP_PKEY, EVP_PKEY_free>;
EVP_PKEYPtr makeEVPPKeyPtr(EVP_PKEY* ptr)
{
    return EVP_PKEYPtr(ptr, EVP_PKEY_free);
}
BIOPtr makeBIOPtr(BIO* ptr)
{
    return BIOPtr(ptr, BIO_free_all);
}
class Tpm2
{
    OSSL_LIB_CTX* libCtx{nullptr};
    void* tpmProviderHandle{nullptr};

    Tpm2()
    {
        libCtx = OSSL_LIB_CTX_new();
        tpmInit();
    }

  public:
    ~Tpm2()
    {
        if (tpmProviderHandle)
        {
            dlclose(tpmProviderHandle);
        }
    }

    void tpmInit()
    {
        // const char* libPath = "/usr/lib/aarch64-linux-gnu/engines-3/tpm2.so";

        // tpmProviderHandle = dlopen(libPath, RTLD_GLOBAL | RTLD_NOW);
        // if (tpmProviderHandle == NULL)
        // {
        //     LOG_ERROR("Failed to load tpm2.so module: {}", dlerror());
        //     return;
        // }

        // OSSL_provider_init_fn* fun = (OSSL_provider_init_fn*)dlsym(
        //     tpmProviderHandle, "OSSL_provider_init_tpm2");

        // if (fun == NULL)
        // {
        //     LOG_ERROR(
        //         "Failed to find OSSL_provider_init_tpm2 in tpm2.so module:
        //         {}", dlerror());
        //     dlclose(tpmProviderHandle);
        //     tpmProviderHandle = nullptr;
        //     return;
        // }

        // fun(libCtx, NULL, NULL);
        OSSL_PROVIDER* tpmProvider = OSSL_PROVIDER_load(libCtx, "tpm2");

        if (tpmProvider)
        {
            // OSSL_PROVIDER_self_test typically runs on load if configured
            // right This manual call is fine, but potentially redundant.
            auto r = OSSL_PROVIDER_self_test(tpmProvider);
            if (r != 1)
            {
                LOG_ERROR("TPM2 provider self test failed");
                return;
            }
            return;
        }

        LOG_ERROR("Failed to load tpm2 provider");
    }

    EVP_PKEYPtr retrievePrivateKeyFromTpm(const std::string& tpmUri)
    {
        OSSL_STORE_CTX* storeCtx = nullptr;
        OSSL_STORE_INFO* info = nullptr;
        const char* propq = "?provider=tpm2";
        EVP_PKEY* pkey = nullptr;

        storeCtx = OSSL_STORE_open_ex(tpmUri.c_str(), libCtx, propq, NULL, NULL,
                                      NULL, NULL, NULL);

        if (!storeCtx)
        {
            LOG_ERROR("Failed to open store context for URI: {}", tpmUri);
            return makeEVPPKeyPtr(nullptr);
        }

        // Iterate until a key is found or end of store reached
        while (!OSSL_STORE_eof(storeCtx) && pkey == nullptr)
        {
            info = OSSL_STORE_load(storeCtx);

            if (info == nullptr)
            {
                if (OSSL_STORE_error(storeCtx))
                {
                    LOG_ERROR("Error during OSSL_STORE_load (PrivateKey).");
                }
                continue;
            }

            if (OSSL_STORE_INFO_get_type(info) == OSSL_STORE_INFO_PKEY)
            {
                pkey = OSSL_STORE_INFO_get1_PKEY(info);
                LOG_INFO("Private key retrieved from TPM.");
            }

            OSSL_STORE_INFO_free(info);
        }

        OSSL_STORE_close(storeCtx);

        if (pkey == nullptr)
        {
            LOG_ERROR("No private key found at URI: {}", tpmUri);
        }

        return makeEVPPKeyPtr(pkey); // Using assumed smart pointer constructor
    }
    X509Ptr retrieveCertificateFromTpm(const std::string& tpmUri)
    {
        OSSL_STORE_CTX* storeCtx = nullptr;
        OSSL_STORE_INFO* info = nullptr;
        const char* propq = "?provider=tpm2";
        X509* cert = nullptr;

        storeCtx = OSSL_STORE_open_ex(tpmUri.c_str(), libCtx, propq, NULL, NULL,
                                      NULL, NULL, NULL);

        if (!storeCtx)
        {
            LOG_ERROR("Failed to open store context for URI: {}", tpmUri);
            return makeX509Ptr(nullptr);
        }

        // Iterate until a certificate is found or end of store reached
        while (!OSSL_STORE_eof(storeCtx) && cert == nullptr)
        {
            info = OSSL_STORE_load(storeCtx);

            if (info == nullptr)
            {
                if (OSSL_STORE_error(storeCtx))
                {
                    LOG_ERROR("Error during OSSL_STORE_load (Certificate).");
                }
                continue;
            }

            if (OSSL_STORE_INFO_get_type(info) == OSSL_STORE_INFO_CERT)
            {
                cert = OSSL_STORE_INFO_get1_CERT(info);
                LOG_INFO("Certificate retrieved from TPM.");
            }

            OSSL_STORE_INFO_free(info);
        }

        OSSL_STORE_close(storeCtx);

        if (cert == nullptr)
        {
            LOG_ERROR("No certificate found at URI: {}", tpmUri);
        }

        return makeX509Ptr(cert); // Using assumed smart pointer constructor
    }

    static Tpm2& getInstance()
    {
        static Tpm2 instance;
        return instance;
    }
};
inline void printLastError()
{
    unsigned long err = ERR_get_error();
    char err_buf[256];
    ERR_error_string_n(err, err_buf, sizeof(err_buf));
    LOG_ERROR("OpenSSL error: {}", err_buf);
}
// Convert PEM certificate file to DER format and save to file
bool pemCertToDer(const std::string& pemPath, const std::string& derPath)
{
    FILE* pemFile = fopen(pemPath.c_str(), "r");
    if (!pemFile)
        return false;
    X509Ptr cert =
        makeX509Ptr(PEM_read_X509(pemFile, nullptr, nullptr, nullptr));
    fclose(pemFile);
    if (!cert)
        return false;

    FILE* derFile = fopen(derPath.c_str(), "wb");
    if (!derFile)
    {
        return false;
    }
    int ret = i2d_X509_fp(derFile, cert.get());
    fclose(derFile);
    return ret == 1;
}

// Convert DER certificate file to PEM format and save to file
bool derCertToPem(const std::string& derPath, const std::string& pemPath)
{
    FILE* derFile = fopen(derPath.c_str(), "rb");
    if (!derFile)
        return false;
    X509Ptr cert = makeX509Ptr(d2i_X509_fp(derFile, nullptr));
    fclose(derFile);
    if (!cert)
        return false;

    FILE* pemFile = fopen(pemPath.c_str(), "w");
    if (!pemFile)
    {
        return false;
    }
    int ret = PEM_write_X509(pemFile, cert.get());
    fclose(pemFile);
    return ret == 1;
}

// Convert PEM private key file to DER format and save to file
bool pemKeyToDer(const std::string& pemPath, const std::string& derPath)
{
    FILE* pemFile = fopen(pemPath.c_str(), "r");
    if (!pemFile)
        return false;
    EVP_PKEYPtr pkey =
        makeEVPPKeyPtr(PEM_read_PrivateKey(pemFile, nullptr, nullptr, nullptr));
    fclose(pemFile);
    if (!pkey)
        return false;

    FILE* derFile = fopen(derPath.c_str(), "wb");
    if (!derFile)
    {
        return false;
    }
    int ret = i2d_PrivateKey_fp(derFile, pkey.get());
    fclose(derFile);

    return ret == 1;
}

// Convert DER private key file to PEM format and save to file
bool derKeyToPem(const std::string& derPath, const std::string& pemPath)
{
    FILE* derFile = fopen(derPath.c_str(), "rb");
    if (!derFile)
        return false;
    EVP_PKEYPtr pkey = makeEVPPKeyPtr(d2i_PrivateKey_fp(derFile, nullptr));
    fclose(derFile);
    if (!pkey)
        return false;

    FILE* pemFile = fopen(pemPath.c_str(), "w");
    if (!pemFile)
    {
        return false;
    }
    int ret = PEM_write_PrivateKey(pemFile, pkey.get(), nullptr, nullptr, 0,
                                   nullptr, nullptr);
    fclose(pemFile);
    return ret == 1;
}

// Convert PEM certificate (in-memory string) to DER (in-memory buffer)
inline bool pemStringToDer(const std::string& pem, std::vector<uint8_t>& der)
{
    if (pem.empty())
        return false;

    BIOPtr inBio = makeBIOPtr(BIO_new_mem_buf(pem.data(), (int)pem.size()));
    if (!inBio)
        return false;

    X509* raw = PEM_read_bio_X509(inBio.get(), nullptr, nullptr, nullptr);
    if (!raw)
        return false;
    X509Ptr cert = makeX509Ptr(raw);

    BIOPtr outBio = makeBIOPtr(BIO_new(BIO_s_mem()));
    if (!outBio)
        return false;

    if (!i2d_X509_bio(outBio.get(), cert.get()))
        return false;

    BUF_MEM* bptr = nullptr;
    BIO_get_mem_ptr(outBio.get(), &bptr);
    if (!bptr || bptr->length == 0)
        return false;

    der.assign(reinterpret_cast<uint8_t*>(bptr->data),
               reinterpret_cast<uint8_t*>(bptr->data) + bptr->length);
    return true;
}

// Convert DER (in-memory buffer) to PEM (in-memory string)
inline bool derToPemString(const std::vector<uint8_t>& der, std::string& pem)
{
    if (der.empty())
        return false;

    BIOPtr inBio = makeBIOPtr(BIO_new_mem_buf(der.data(), (int)der.size()));
    if (!inBio)
        return false;

    X509* raw = d2i_X509_bio(inBio.get(), nullptr);
    if (!raw)
        return false;
    X509Ptr cert = makeX509Ptr(raw);

    BIOPtr outBio = makeBIOPtr(BIO_new(BIO_s_mem()));
    if (!outBio)
        return false;

    if (!PEM_write_bio_X509(outBio.get(), cert.get()))
        return false;

    BUF_MEM* bptr = nullptr;
    BIO_get_mem_ptr(outBio.get(), &bptr);
    if (!bptr || bptr->length == 0)
        return false;

    pem.assign(bptr->data, bptr->data + bptr->length);
    return true;
}

// Read PEM certificate file and return DER buffer
inline bool pemCertFileToDerBuffer(const std::string& pemPath,
                                   std::vector<uint8_t>& der)
{
    std::ifstream in(pemPath, std::ios::in | std::ios::binary);
    if (!in)
        return false;
    std::string pem((std::istreambuf_iterator<char>(in)),
                    std::istreambuf_iterator<char>());
    return pemStringToDer(pem, der);
}

// Read DER certificate file and return PEM string
inline bool derFileToPemString(const std::string& derPath, std::string& pem)
{
    std::ifstream in(derPath, std::ios::in | std::ios::binary);
    if (!in)
        return false;
    std::vector<uint8_t> buf((std::istreambuf_iterator<char>(in)),
                             std::istreambuf_iterator<char>());
    return derToPemString(buf, pem);
}

// Write DER certificate file from PEM string
inline bool pemStringToDerFile(const std::string& pem,
                               const std::string& derPath)
{
    std::vector<uint8_t> der;
    if (!pemStringToDer(pem, der))
        return false;
    std::ofstream out(derPath, std::ios::out | std::ios::binary);
    if (!out)
        return false;
    out.write(reinterpret_cast<const char*>(der.data()),
              (std::streamsize)der.size());
    return out.good();
}

// Write PEM certificate file from DER buffer
inline bool derBufferToPemCertFile(const std::vector<uint8_t>& der,
                                   const std::string& pemPath)
{
    std::string pem;
    if (!derToPemString(der, pem))
        return false;
    std::ofstream out(pemPath, std::ios::out | std::ios::binary);
    if (!out)
        return false;
    out.write(pem.data(), (std::streamsize)pem.size());
    return out.good();
}

// Read PEM private key file and return DER buffer
inline bool pemKeyFileToDerBuffer(const std::string& pemPath,
                                  std::vector<uint8_t>& der)
{
    std::ifstream in(pemPath, std::ios::in | std::ios::binary);
    if (!in)
        return false;
    std::string pem((std::istreambuf_iterator<char>(in)),
                    std::istreambuf_iterator<char>());
    return pemKeyStringToDer(pem, der);
}

// Read DER private key file and return PEM string
inline bool derKeyFileToPemString(const std::string& derPath, std::string& pem)
{
    std::ifstream in(derPath, std::ios::in | std::ios::binary);
    if (!in)
        return false;
    std::vector<uint8_t> buf((std::istreambuf_iterator<char>(in)),
                             std::istreambuf_iterator<char>());
    return derKeyToPemString(buf, pem);
}

// Write DER private key file from PEM string
inline bool pemKeyStringToDerFile(const std::string& pem,
                                  const std::string& derPath)
{
    std::vector<uint8_t> der;
    if (!pemKeyStringToDer(pem, der))
        return false;
    std::ofstream out(derPath, std::ios::out | std::ios::binary);
    if (!out)
        return false;
    out.write(reinterpret_cast<const char*>(der.data()),
              (std::streamsize)der.size());
    return out.good();
}

// Write PEM private key file from DER buffer
inline bool derBufferToPemKeyFile(const std::vector<uint8_t>& der,
                                  const std::string& pemPath)
{
    std::string pem;
    if (!derKeyToPemString(der, pem))
        return false;
    std::ofstream out(pemPath, std::ios::out | std::ios::binary);
    if (!out)
        return false;
    out.write(pem.data(), (std::streamsize)pem.size());
    return out.good();
}

// Convert PEM private key (in-memory string) to DER (in-memory buffer)
inline bool pemKeyStringToDer(const std::string& pem, std::vector<uint8_t>& der)
{
    if (pem.empty())
        return false;

    BIOPtr inBio = makeBIOPtr(BIO_new_mem_buf(pem.data(), (int)pem.size()));
    if (!inBio)
        return false;

    EVP_PKEY* raw =
        PEM_read_bio_PrivateKey(inBio.get(), nullptr, nullptr, nullptr);
    if (!raw)
        return false;
    EVP_PKEYPtr pkey = makeEVPPKeyPtr(raw);

    BIOPtr outBio = makeBIOPtr(BIO_new(BIO_s_mem()));
    if (!outBio)
        return false;

    if (!i2d_PrivateKey_bio(outBio.get(), pkey.get()))
        return false;

    BUF_MEM* bptr = nullptr;
    BIO_get_mem_ptr(outBio.get(), &bptr);
    if (!bptr || bptr->length == 0)
        return false;

    der.assign(reinterpret_cast<uint8_t*>(bptr->data),
               reinterpret_cast<uint8_t*>(bptr->data) + bptr->length);
    return true;
}

// Convert DER private key (in-memory buffer) to PEM (in-memory string)
inline bool derKeyToPemString(const std::vector<uint8_t>& der, std::string& pem)
{
    if (der.empty())
        return false;

    BIOPtr inBio = makeBIOPtr(BIO_new_mem_buf(der.data(), (int)der.size()));
    if (!inBio)
        return false;

    EVP_PKEY* raw = d2i_PrivateKey_bio(inBio.get(), nullptr);
    if (!raw)
        return false;
    EVP_PKEYPtr pkey = makeEVPPKeyPtr(raw);

    BIOPtr outBio = makeBIOPtr(BIO_new(BIO_s_mem()));
    if (!outBio)
        return false;

    if (!PEM_write_bio_PrivateKey(outBio.get(), pkey.get(), nullptr, nullptr, 0,
                                  nullptr, nullptr))
        return false;

    BUF_MEM* bptr = nullptr;
    BIO_get_mem_ptr(outBio.get(), &bptr);
    if (!bptr || bptr->length == 0)
        return false;

    pem.assign(bptr->data, bptr->data + bptr->length);
    return true;
}

openssl_ptr<EVP_PKEY, EVP_PKEY_free> loadPrivateKey(const std::string& path,
                                                    bool pem = true)
{
    BIO* keybio = BIO_new_file(path.data(), "r");
    if (!keybio)
        return {nullptr, EVP_PKEY_free};
    EVP_PKEY* pkey{nullptr};
    if (pem)
    {
        pkey = PEM_read_bio_PrivateKey(keybio, nullptr, nullptr, nullptr);
    }
    else
    {
        pkey = d2i_PrivateKey_bio(keybio, nullptr);
    }

    BIO_free(keybio);
    return openssl_ptr<EVP_PKEY, EVP_PKEY_free>(pkey, EVP_PKEY_free);
}
openssl_ptr<X509, X509_free> loadCertificate(const std::string& path,
                                             bool pem = true)
{
    BIO* certbio = BIO_new_file(path.data(), "r");
    if (!certbio)
        return {nullptr, X509_free};
    X509* cert{nullptr};
    if (pem)
    {
        cert = PEM_read_bio_X509(certbio, nullptr, nullptr, nullptr);
    }
    else
    {
        cert = d2i_X509_bio(certbio, nullptr);
    }
    BIO_free(certbio);
    return openssl_ptr<X509, X509_free>(cert, X509_free);
}
openssl_ptr<X509_NAME, X509_NAME_free> generateX509Name(
    const std::string& common_name)
{
    openssl_ptr<X509_NAME, X509_NAME_free> name(X509_NAME_new(),
                                                X509_NAME_free);
    if (!name)
        return {nullptr, X509_NAME_free};
    X509_NAME_add_entry_by_txt(name.get(), "C", MBSTRING_ASC,
                               (const unsigned char*)"US", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name.get(), "ST", MBSTRING_ASC,
                               (const unsigned char*)"CAL", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name.get(), "L", MBSTRING_ASC,
                               (const unsigned char*)"EN", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name.get(), "O", MBSTRING_ASC,
                               (const unsigned char*)"OpenBMC", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name.get(), "OU", MBSTRING_ASC,
                               (const unsigned char*)"SPDM", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name.get(), "CN", MBSTRING_ASC,
                               (const unsigned char*)common_name.data(), -1, -1,
                               0);

    return name;
}
openssl_ptr<EVP_PKEY, EVP_PKEY_free> generate_key_pair()
{
    // Create an EVP_PKEY_CTX for RSA key generation.
    openssl_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_free> pkey_ctx(
        EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr), EVP_PKEY_CTX_free);
    if (!pkey_ctx)
    {
        // Handle error
        return makeEVPPKeyPtr(nullptr);
    }

    if (EVP_PKEY_keygen_init(pkey_ctx.get()) <= 0)
    {
        // Handle error
        return makeEVPPKeyPtr(nullptr);
    }

    // Use OSSL_PARAM_BLD to construct the parameter list.
    openssl_ptr<OSSL_PARAM_BLD, OSSL_PARAM_BLD_free> param_bld(
        OSSL_PARAM_BLD_new(), OSSL_PARAM_BLD_free);
    if (!param_bld)
    {
        return makeEVPPKeyPtr(nullptr);
    }

    // Set the key size parameter.
    if (OSSL_PARAM_BLD_push_int(param_bld.get(), OSSL_PKEY_PARAM_RSA_BITS,
                                2048) <= 0)
    {
        return makeEVPPKeyPtr(nullptr);
    }

    // Set the public exponent parameter.

    openssl_ptr<BIGNUM, BN_free> e(BN_new(), BN_free);
    if (!e || !BN_set_word(e.get(), RSA_F4))
    {
        return makeEVPPKeyPtr(nullptr);
    }
    if (OSSL_PARAM_BLD_push_BN(param_bld.get(), OSSL_PKEY_PARAM_RSA_E,
                               e.get()) <= 0)
    {
        return makeEVPPKeyPtr(nullptr);
    }

    // Build the OSSL_PARAM array from the builder.
    openssl_ptr<OSSL_PARAM, OSSL_PARAM_free> params(
        OSSL_PARAM_BLD_to_param(param_bld.get()), OSSL_PARAM_free);
    if (!params)
    {
        return makeEVPPKeyPtr(nullptr);
    }

    // Set all parameters on the keygen context at once.
    if (EVP_PKEY_CTX_set_params(pkey_ctx.get(), params.get()) <= 0)
    {
        return makeEVPPKeyPtr(nullptr);
    }

    // Generate the key pair directly into an EVP_PKEY object.
    EVP_PKEY* raw_pkey = nullptr;
    if (EVP_PKEY_keygen(pkey_ctx.get(), &raw_pkey) <= 0)
    {
        return makeEVPPKeyPtr(nullptr);
    }

    return makeEVPPKeyPtr(raw_pkey);
}

bool isSignedByCA(const openssl_ptr<X509, X509_free>& cert,
                  const openssl_ptr<EVP_PKEY, EVP_PKEY_free>& ca_pubkey)
{
    if (!cert || !ca_pubkey)
        return false;
    // Returns 1 if signature is valid, 0 if not, -1 on error
    int result = X509_verify(cert.get(), ca_pubkey.get());
    if (result != 1)
    {
        printLastError();
        LOG_ERROR("Certificate signature verification failed");
    }
    return true;
}
// Create a new X509 certificate, signed by issuer_pkey, with subject/issuer
// names
inline openssl_ptr<X509, X509_free> create_certificate(
    EVP_PKEY* subject_key, X509_NAME* subject_name, EVP_PKEY* issuer_pkey,
    X509_NAME* issuer_name, int days_valid, bool is_ca)
{
    if (!subject_key || !subject_name || !issuer_pkey || !issuer_name)
    {
        LOG_ERROR("Invalid parameters for certificate creation");
        return makeX509Ptr(nullptr);
    }
    openssl_ptr<X509, X509_free> cert(X509_new(), X509_free);
    ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), std::rand());
    X509_gmtime_adj(X509_get_notBefore(cert.get()), -60); // 1 minute back
    X509_gmtime_adj(X509_get_notAfter(cert.get()),
                    60L * 60L * 24L * days_valid);
    X509_set_pubkey(cert.get(), subject_key);
    X509_set_subject_name(cert.get(), subject_name);
    X509_set_issuer_name(cert.get(), issuer_name);

    X509_set_version(cert.get(), 2); // Set certificate version to v3

    // Add basicConstraints
    X509_EXTENSION* ext;
    ext = X509V3_EXT_conf_nid(nullptr, nullptr, NID_basic_constraints,
                              is_ca ? (char*)"CA:TRUE" : (char*)"CA:FALSE");
    X509_add_ext(cert.get(), ext, -1);
    X509_EXTENSION_free(ext);

    // Add keyUsage
    if (is_ca)
    {
        ext = X509V3_EXT_conf_nid(
            nullptr, nullptr, NID_key_usage,
            (char*)"keyCertSign, cRLSign, digitalSignature, keyEncipherment");
    }
    else
    {
        ext = X509V3_EXT_conf_nid(nullptr, nullptr, NID_key_usage,
                                  (char*)"digitalSignature,"
                                         " keyEncipherment");
    }
    X509_add_ext(cert.get(), ext, -1);
    X509_EXTENSION_free(ext);

    int sign_result = X509_sign(cert.get(), issuer_pkey, EVP_sha256());
    if (sign_result <= 0)
    {
        printLastError();
        LOG_ERROR("Failed to sign certificate");
        return makeX509Ptr(nullptr);
    }
    return cert;
}

// Create an intermediate CA certificate signed by root CA
inline std::pair<X509Ptr, EVP_PKEYPtr> create_ca_cert(
    EVP_PKEY* signkey, X509_NAME* signname, const std::string& common_name,
    int days_valid = 365)
{
    auto pkey = generate_key_pair();
    openssl_ptr<X509_NAME, X509_NAME_free> name = generateX509Name(common_name);
    if (!name)
    {
        LOG_ERROR("Failed to create X509 name for common name: {}",
                  common_name);
        return std::make_pair(X509Ptr(nullptr, X509_free),
                              EVP_PKEYPtr(nullptr, EVP_PKEY_free));
    }

    if (signkey)
    {
        auto ca = create_certificate(
            pkey.get(), name.get(), signkey, signname, days_valid,
            true // is_ca
        );
        return std::make_pair(std::move(ca), std::move(pkey));
    }
    auto ca = create_certificate(
        pkey.get(), name.get(), pkey.get(), name.get(), days_valid,
        true // is_ca
    );
    return std::make_pair(std::move(ca), std::move(pkey));
}

// Create an entity certificate signed by CA (root or intermediate)
inline std::pair<X509Ptr, EVP_PKEYPtr> create_leaf_cert(
    EVP_PKEY* ca_pkey, X509_NAME* ca_name, const std::string& common_name,
    int days_valid = 365)
{
    auto pkey = generate_key_pair();
    auto name = generateX509Name(common_name);

    auto cert = create_certificate(pkey.get(), name.get(), ca_pkey, ca_name,
                                   days_valid, false);
    return std::make_pair(std::move(cert), std::move(pkey));
}

bool checkValidity(const openssl_ptr<X509, X509_free>& cert)
{
    if (!cert)
    {
        LOG_ERROR("Certificate pointer is null");
        return false;
    }

    // Check validity period
    if (X509_cmp_current_time(X509_get_notBefore(cert.get())) > 0)
    {
        LOG_ERROR("Certificate is not yet valid");
        return false;
    }
    if (X509_cmp_current_time(X509_get_notAfter(cert.get())) < 0)
    {
        LOG_ERROR("Certificate has expired");
        return false;
    }

    // Check subject
    X509_NAME* subject = X509_get_subject_name(cert.get());
    if (!subject || X509_NAME_entry_count(subject) == 0)
    {
        LOG_ERROR("Certificate subject is invalid or missing");
        return false;
    }

    // Check issuer
    X509_NAME* issuer = X509_get_issuer_name(cert.get());
    if (!issuer || X509_NAME_entry_count(issuer) == 0)
    {
        LOG_ERROR("Certificate issuer is invalid or missing");
        return false;
    }

    // Check public key
    EVP_PKEY* pubkey = X509_get_pubkey(cert.get());
    if (!pubkey)
    {
        LOG_ERROR("Certificate public key is invalid or missing");
        return false;
    }
    if (EVP_PKEY_base_id(pubkey) != EVP_PKEY_RSA &&
        EVP_PKEY_base_id(pubkey) != EVP_PKEY_EC)
    {
        LOG_ERROR("Certificate public key is not RSA or EC");
        EVP_PKEY_free(pubkey);
        return false;
    }
    EVP_PKEY_free(pubkey);

    // Check serial number
    ASN1_INTEGER* serial = X509_get_serialNumber(cert.get());
    if (!serial || ASN1_INTEGER_get(serial) <= 0)
    {
        LOG_ERROR("Certificate serial number is invalid or missing");
        return false;
    }

    // Check signature algorithm
    const X509_ALGOR* sig_alg = X509_get0_tbs_sigalg(cert.get());
    if (!sig_alg)
    {
        LOG_ERROR("Certificate signature algorithm is missing");
        return false;
    }

    // Check if certificate is signed
    // if (X509_verify(cert.get(), X509_get_pubkey(cert.get())) != 1)
    // {
    //     LOG_ERROR("Certificate signature verification failed");
    //     return false;
    // }

    // Optionally check for required extensions (e.g., basicConstraints,
    // keyUsage)
    int ext_index = X509_get_ext_by_NID(cert.get(), NID_basic_constraints, -1);
    if (ext_index < 0)
    {
        LOG_ERROR("Certificate missing basicConstraints extension");
        return false;
    }

    // Optionally check version (should be v3 for most use cases)
    if (X509_get_version(cert.get()) != 2)
    {
        LOG_ERROR("Certificate version is not v3");
        return false;
    }

    return true;
}
bool saveBio(const std::string& path, const openssl_ptr<BIO, BIO_free_all>& bio)
{
    if (!bio)
    {
        LOG_ERROR("BIO pointer is null, cannot save to file {}", path);
        return false;
    }
    std::ofstream file(path);
    if (!file.is_open())
    {
        LOG_ERROR("Failed to open file {} for writing", path);
        return false;
    }
    BUF_MEM* buf;
    BIO_get_mem_ptr(bio.get(), &buf);
    file.write(buf->data, buf->length);
    file.close();
    LOG_DEBUG("BIO data saved to {}", path);
    return true;
}
openssl_ptr<BIO, BIO_free_all> loadCertificate(
    const openssl_ptr<X509, X509_free>& cert, bool pem = true)
{
    if (!checkValidity(cert))
    {
        LOG_ERROR("Certificate is not valid, cannot save to buffer");
        return makeBIOPtr(nullptr);
    }
    auto bio = makeBIOPtr(BIO_new(BIO_s_mem()));
    if (pem)
    {
        if (!PEM_write_bio_X509(bio.get(), cert.get()))
        {
            printLastError();
            LOG_ERROR("Failed to write certificate to buffer");
            return makeBIOPtr(nullptr);
        }
    }
    else
    {
        if (!i2d_X509_bio(bio.get(), cert.get()))
        {
            printLastError();
            LOG_ERROR("Failed to write certificate to buffer");
            return makeBIOPtr(nullptr);
        }
    }
    return bio;
}
bool saveCertificate(const std::string& path,
                     const openssl_ptr<X509, X509_free>& cert, bool pem = true)
{
    if (!saveBio(path, loadCertificate(cert, pem)))
    {
        LOG_ERROR("Failed to save certificate to file {}", path);
        return false;
    }
    LOG_DEBUG("Certificate saved to {}", path);
    return true;
}
bool saveCertificate(const std::string& path, const std::vector<X509*>& certs,
                     bool pem = true)
{
    if (certs.empty())
    {
        LOG_ERROR("Certificate chain is empty, nothing to save");
        return false;
    }
    openssl_ptr<BIO, BIO_free_all> bio(BIO_new(BIO_s_mem()), BIO_free_all);
    for (const auto& cert : certs)
    {
        if (!cert)
        {
            LOG_ERROR("Invalid certificate in chain, skipping");
            continue;
        }
        if (pem)
        {
            if (!PEM_write_bio_X509(bio.get(), cert))
            {
                LOG_ERROR("Failed to write certificate to BIO");
                return false;
            }
        }
        else
        {
            if (!i2d_X509_bio(bio.get(), cert))
            {
                LOG_ERROR("Failed to write certificate to BIO");
                return false;
            }
        }
    }
    return saveBio(path, std::move(bio));
}

openssl_ptr<BIO, BIO_free_all> loadPrivateKey(
    const openssl_ptr<EVP_PKEY, EVP_PKEY_free>& pkey, bool pem = true)
{
    openssl_ptr<BIO, BIO_free_all> bio(BIO_new(BIO_s_mem()), BIO_free_all);
    if (pem)
    {
        if (!PEM_write_bio_PrivateKey(bio.get(), pkey.get(), nullptr, nullptr,
                                      0, nullptr, nullptr))
        {
            LOG_ERROR("Failed to write private key to BIO");
            return makeBIOPtr(nullptr);
        }
    }
    else
    {
        if (!i2d_PrivateKey_bio(bio.get(), pkey.get()))
        {
            LOG_ERROR("Failed to write private key to BIO");
            return makeBIOPtr(nullptr);
        }
    }
    return bio;
}
bool savePrivateKey(const std::string& path,
                    const openssl_ptr<EVP_PKEY, EVP_PKEY_free>& pkey,
                    bool pem = true)
{
    if (!saveBio(path, loadPrivateKey(pkey, pem)))
    {
        LOG_ERROR("Failed to save private key to file {}", path);
        return false;
    }
    LOG_DEBUG("Private key saved to {}", path);
    return true;
}
std::string toString(const openssl_ptr<X509, X509_free>& cert, bool pem = true)
{
    auto bio = loadCertificate(cert, pem);
    if (!bio)
    {
        LOG_ERROR("Failed to load certificate into BIO");
        return {};
    }

    BUF_MEM* buf;
    BIO_get_mem_ptr(bio.get(), &buf);
    return std::string(buf->data, buf->length);
}
std::string toString(const openssl_ptr<EVP_PKEY, EVP_PKEY_free>& pkey,
                     bool pem = true)
{
    auto bio = loadPrivateKey(pkey, pem);
    if (!bio)
    {
        LOG_ERROR("Failed to load private key into BIO");
        return {};
    }
    BUF_MEM* buf;
    BIO_get_mem_ptr(bio.get(), &buf);
    return std::string(buf->data, buf->length);
}
EVP_PKEYPtr getPublicKeyFromCert(const openssl_ptr<X509, X509_free>& cert)
{
    if (!cert)
    {
        LOG_ERROR("Certificate pointer is null");
        return {nullptr, EVP_PKEY_free};
    }
    auto pkey = makeEVPPKeyPtr(X509_get_pubkey(cert.get()));
    if (!pkey)
    {
        LOG_ERROR("Failed to get public key from certificate");
    }
    return pkey;
}
std::string getPublicKeyStringFromCert(X509Ptr signcert)
{
    if (!signcert)
    {
        LOG_ERROR("Failed to read certificate from string");
        return {};
    }
    auto pkey = getPublicKeyFromCert(signcert);
    if (!pkey)
    {
        LOG_ERROR("Error: Unable to get public key from certificate.");
        return std::string();
    }
    openssl_ptr<BIO, BIO_free_all> bio(BIO_new(BIO_s_mem()), BIO_free_all);
    if (!PEM_write_bio_PUBKEY(bio.get(), pkey.get()))
    {
        LOG_ERROR("Failed to write certificate to BIO");
        return {};
    }

    BUF_MEM* buf;
    BIO_get_mem_ptr(bio.get(), &buf);
    return std::string(buf->data, buf->length);
}
} // namespace NSNAME
