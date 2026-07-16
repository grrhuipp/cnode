#include "autosign_cert.hpp"

#include <openssl/ec.h>
#include <openssl/x509v3.h>

#include <limits>
#include <string_view>

namespace acpp::transport::internet {
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
    if (value.size() > static_cast<size_t>(std::numeric_limits<int>::max())) {
        return false;
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

AutoSignState::~AutoSignState() {
    ClearCertCache();
    if (pkey_) EVP_PKEY_free(pkey_);
}

AutoSignMaterial AutoSignState::GetOrCreate(const std::string& cn) {
    return GetOrCreate(cn, Clock::now());
}

AutoSignMaterial AutoSignState::GetOrCreate(const std::string& cn, Clock::time_point now) {
    if (!EnsureKey(now)) {
        return {};
    }

    if (auto it = cert_cache_.find(cn); it != cert_cache_.end()) {
        cert_lru_.splice(cert_lru_.begin(), cert_lru_, it->second.lru_it);
        return {it->second.cert, pkey_};
    }

    X509* x509 = X509_new();
    if (!x509) return {};

    X509_NAME* name = X509_get_subject_name(x509);
    const auto validity_seconds = static_cast<long>(
        std::chrono::duration_cast<std::chrono::seconds>(
            kRotateInterval).count());
    if (X509_set_version(x509, 2) != 1 ||
        ASN1_INTEGER_set(X509_get_serialNumber(x509), next_serial_++) != 1 ||
        !X509_gmtime_adj(X509_get_notBefore(x509), 0) ||
        !X509_gmtime_adj(X509_get_notAfter(x509), validity_seconds) ||
        X509_set_pubkey(x509, pkey_) != 1 ||
        !name ||
        X509_NAME_add_entry_by_txt(
            name, "CN", MBSTRING_ASC,
            reinterpret_cast<const unsigned char*>(cn.data()),
            static_cast<int>(cn.size()), -1, 0) != 1 ||
        X509_set_issuer_name(x509, name) != 1 ||
        !AddSubjectAlternativeNames(x509, cn) ||
        X509_sign(x509, pkey_, EVP_sha256()) <= 0) {
        X509_free(x509);
        return {};
    }

    while (cert_cache_.size() >= kMaxCachedCerts && !cert_lru_.empty()) {
        auto victim = std::prev(cert_lru_.end());
        auto victim_it = cert_cache_.find(*victim);
        if (victim_it != cert_cache_.end()) {
            X509_free(victim_it->second.cert);
            cert_cache_.erase(victim_it);
        }
        cert_lru_.erase(victim);
    }

    cert_lru_.push_front(cn);
    cert_cache_.emplace(cn, CachedCert{x509, cert_lru_.begin()});
    return {x509, pkey_};
}

bool AutoSignState::EnsureKey(Clock::time_point now) {
    const bool expired = pkey_ && now - key_created_at_ >= kRotateInterval;
    if (pkey_ && !expired) {
        return true;
    }

    EVP_PKEY* generated = GenerateEcP256Key();
    if (!generated) {
        return pkey_ != nullptr;
    }

    ClearCertCache();
    if (pkey_) EVP_PKEY_free(pkey_);
    pkey_ = generated;
    key_created_at_ = now;
    return true;
}

void AutoSignState::ClearCertCache() {
    for (auto& [_, cached] : cert_cache_) {
        X509_free(cached.cert);
    }
    cert_cache_.clear();
    cert_lru_.clear();
}

}  // namespace acpp::transport::internet
