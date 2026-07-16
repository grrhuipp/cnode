#include "autosign_cert.hpp"

#include <openssl/ec.h>
#include <openssl/x509v3.h>

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

    X509_set_version(x509, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x509), next_serial_++);

    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509),
                    static_cast<long>(std::chrono::duration_cast<std::chrono::seconds>(
                        kRotateInterval).count()));

    X509_set_pubkey(x509, pkey_);

    X509_NAME* name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
        reinterpret_cast<const unsigned char*>(cn.c_str()), -1, -1, 0);
    X509_set_issuer_name(x509, name);

    X509V3_CTX v3ctx;
    X509V3_set_ctx_nodb(&v3ctx);
    X509V3_set_ctx(&v3ctx, x509, x509, nullptr, nullptr, 0);
    ASN1_OCTET_STRING* ip_address = a2i_IPADDRESS(cn.c_str());
    const bool is_ip_address = ip_address != nullptr;
    if (ip_address) ASN1_OCTET_STRING_free(ip_address);
    std::string san_val = (is_ip_address ? "IP:" : "DNS:") + cn;
    if (!is_ip_address && cn.size() > 2 && cn[0] == '*' && cn[1] == '.') {
        san_val += ",DNS:" + cn.substr(2);
    }
    X509_EXTENSION* san_ext = X509V3_EXT_nconf_nid(
        nullptr, &v3ctx, NID_subject_alt_name, const_cast<char*>(san_val.c_str()));
    if (san_ext) {
        X509_add_ext(x509, san_ext, -1);
        X509_EXTENSION_free(san_ext);
    }

    if (!X509_sign(x509, pkey_, EVP_sha256())) {
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
