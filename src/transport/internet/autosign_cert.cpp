#include "autosign_cert.hpp"

#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

#include <limits>
#include <string>
#include <string_view>

namespace transport::internet {
namespace {

EVP_PKEY* GenerateEcP256Key() {
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    EVP_PKEY* generated = nullptr;
    if (!pctx ||
        EVP_PKEY_keygen_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) <= 0 ||
        EVP_PKEY_keygen(pctx, &generated) <= 0) {
        if (pctx) EVP_PKEY_CTX_free(pctx);
        if (generated) EVP_PKEY_free(generated);
        return nullptr;
    }
    EVP_PKEY_CTX_free(pctx);
    return generated;
}

bool PushGeneralName(GENERAL_NAMES* names, int type, ASN1_STRING* value) {
    GENERAL_NAME* name = GENERAL_NAME_new();
    if (!name) {
        ASN1_STRING_free(value);
        return false;
    }
    GENERAL_NAME_set0_value(name, type, value);
    if (sk_GENERAL_NAME_push(names, name) == 0) {
        GENERAL_NAME_free(name);
        return false;
    }
    return true;
}

bool PushDnsName(GENERAL_NAMES* names, std::string_view value) {
    if (value.empty() ||
        value.size() > static_cast<size_t>(std::numeric_limits<int>::max())) {
        return false;
    }
    for (const unsigned char ch : value) {
        if (ch <= 0x20 || ch > 0x7e) return false;
    }
    ASN1_IA5STRING* dns_name = ASN1_IA5STRING_new();
    if (!dns_name ||
        ASN1_STRING_set(
            dns_name, value.data(), static_cast<int>(value.size())) != 1) {
        if (dns_name) ASN1_IA5STRING_free(dns_name);
        return false;
    }
    return PushGeneralName(names, GEN_DNS, dns_name);
}

bool AddSubjectAlternativeNames(X509* certificate, const std::string& identity) {
    GENERAL_NAMES* names = GENERAL_NAMES_new();
    if (!names) return false;

    ASN1_OCTET_STRING* ip_address = a2i_IPADDRESS(identity.c_str());
    bool built = false;
    if (ip_address) {
        built = PushGeneralName(names, GEN_IPADD, ip_address);
    } else {
        built = PushDnsName(names, identity);
        if (built && identity.starts_with("*.")) {
            built = PushDnsName(names, std::string_view(identity).substr(2));
        }
    }

    X509_EXTENSION* extension = built
        ? X509V3_EXT_i2d(NID_subject_alt_name, 0, names)
        : nullptr;
    const bool added = extension && X509_add_ext(certificate, extension, -1) == 1;
    if (extension) X509_EXTENSION_free(extension);
    GENERAL_NAMES_free(names);
    return added;
}

}  // namespace

AutoSignCertificate::~AutoSignCertificate() {
    X509_free(certificate_);
    EVP_PKEY_free(key_);
}

std::unique_ptr<AutoSignCertificate> AutoSignCertificate::Create(std::string_view identity) {
    // RFC 5280's commonName limit is 64 characters, not a DNS SAN limit.
    // DNS identities belong in SAN; a descriptive CN covers longer names.
    if (identity.empty() || identity.find('\0') != std::string_view::npos) return {};
    if (identity.ends_with('.')) identity.remove_suffix(1);
    if (identity.empty() || identity.ends_with('.')) return {};
    const std::string name_text(identity);
    const std::string_view cn = identity.size() <= 64
        ? identity : std::string_view("acppnode self-signed certificate");
    auto material = std::unique_ptr<AutoSignCertificate>(new AutoSignCertificate);
    material->key_ = GenerateEcP256Key();
    material->certificate_ = X509_new();
    if (!material->key_ || !material->certificate_) {
        ERR_clear_error();
        return {};
    }
    X509* x509 = material->certificate_;
    X509_NAME* name = X509_get_subject_name(x509);
    // These credentials are regenerated on configuration reload/restart,
    // never in response to untrusted ClientHello traffic.
    constexpr long kValiditySeconds = 365L * 24 * 60 * 60;
    if (X509_set_version(x509, 2) != 1 ||
        ASN1_INTEGER_set(X509_get_serialNumber(x509), 1) != 1 ||
        !X509_gmtime_adj(X509_get_notBefore(x509), -300) ||
        !X509_gmtime_adj(X509_get_notAfter(x509), kValiditySeconds) ||
        X509_set_pubkey(x509, material->key_) != 1 ||
        !name ||
        X509_NAME_add_entry_by_txt(
            name, "CN", MBSTRING_ASC,
            reinterpret_cast<const unsigned char*>(cn.data()),
            static_cast<int>(cn.size()), -1, 0) != 1 ||
        X509_set_issuer_name(x509, name) != 1 ||
        !AddSubjectAlternativeNames(x509, name_text) ||
        X509_sign(x509, material->key_, EVP_sha256()) <= 0) {
        ERR_clear_error();
        return {};
    }
    return material;
}

}  // namespace transport::internet
