#![allow(missing_docs, non_camel_case_types)]
#![cfg(feature = "impit")]
use alloc::vec::Vec;

use crate::msgs::enums::ExtensionType;
use crate::{NamedGroup, SignatureScheme, SupportedCipherSuite};

use super::{WebPkiSupportedAlgorithms, aws_lc_rs};
use webpki::aws_lc_rs as webpki_algs;

/// TLS fingerprint configuration for browser emulation.
///
/// This struct allows fine-grained control over TLS parameters
/// to match specific browser fingerprints.
#[derive(Clone, Debug)]
pub struct TlsFingerprint {
    /// Cipher suites in preference order
    pub cipher_suites: Vec<FingerprintCipherSuite>,
    /// Key exchange groups in preference order
    pub key_exchange_groups: Vec<FingerprintKeyExchangeGroup>,
    /// Signature algorithms in preference order
    pub signature_algorithms: Vec<FingerprintSignatureAlgorithm>,
    /// TLS extensions configuration
    pub extensions: TlsExtensionsConfig,
    /// ALPN protocols in preference order
    pub alpn_protocols: Vec<Vec<u8>>,
    /// Certificate compression algorithms
    pub cert_compression: Option<Vec<FingerprintCertCompressionAlgorithm>>,
}

impl TlsFingerprint {
    /// Creates a new TLS fingerprint with the given configuration.
    pub fn new(
        cipher_suites: Vec<FingerprintCipherSuite>,
        key_exchange_groups: Vec<FingerprintKeyExchangeGroup>,
        signature_algorithms: Vec<FingerprintSignatureAlgorithm>,
        extensions: TlsExtensionsConfig,
        alpn_protocols: Vec<Vec<u8>>,
        cert_compression: Option<Vec<FingerprintCertCompressionAlgorithm>>,
    ) -> Self {
        Self {
            cipher_suites,
            key_exchange_groups,
            signature_algorithms,
            extensions,
            alpn_protocols,
            cert_compression,
        }
    }
}

/// TLS cipher suites for fingerprinting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FingerprintCipherSuite {
    // TLS 1.3 cipher suites
    TLS13_AES_128_GCM_SHA256,
    TLS13_AES_256_GCM_SHA384,
    TLS13_CHACHA20_POLY1305_SHA256,
    // TLS 1.2 cipher suites
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
    TLS_RSA_WITH_AES_128_GCM_SHA256,
    TLS_RSA_WITH_AES_256_GCM_SHA384,
    TLS_RSA_WITH_AES_128_CBC_SHA,
    TLS_RSA_WITH_AES_256_CBC_SHA,
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
    // Legacy 3DES suites: advertise-only. aws-lc-rs does not implement
    // these, so they are excluded from negotiation but their codepoints
    // are sent in the ClientHello to match real-world fingerprints.
    TLS_RSA_WITH_3DES_EDE_CBC_SHA,
    TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
    TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
    /// GREASE cipher suite
    Grease,
}

impl FingerprintCipherSuite {
    /// Returns the CipherSuite code to advertise in the ClientHello.
    /// This returns the actual cipher suite code, even for cipher suites
    /// that are not implemented (like 3DES).
    pub fn to_cipher_suite(&self) -> crate::CipherSuite {
        use crate::CipherSuite;
        match self {
            Self::TLS13_AES_128_GCM_SHA256 => CipherSuite::TLS13_AES_128_GCM_SHA256,
            Self::TLS13_AES_256_GCM_SHA384 => CipherSuite::TLS13_AES_256_GCM_SHA384,
            Self::TLS13_CHACHA20_POLY1305_SHA256 => CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
            Self::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 => {
                CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            }
            Self::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 => {
                CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            }
            Self::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 => {
                CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            }
            Self::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => {
                CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
            }
            Self::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 => {
                CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
            }
            Self::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => {
                CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
            }
            Self::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA => {
                CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
            }
            Self::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA => {
                CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
            }
            Self::TLS_RSA_WITH_AES_128_GCM_SHA256 => CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256,
            Self::TLS_RSA_WITH_AES_256_GCM_SHA384 => CipherSuite::TLS_RSA_WITH_AES_256_GCM_SHA384,
            Self::TLS_RSA_WITH_AES_128_CBC_SHA => CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA,
            Self::TLS_RSA_WITH_AES_256_CBC_SHA => CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA,
            Self::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA => {
                CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
            }
            Self::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA => {
                CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
            }
            Self::TLS_RSA_WITH_3DES_EDE_CBC_SHA => CipherSuite::TLS_RSA_WITH_3DES_EDE_CBC_SHA,
            Self::TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA => {
                CipherSuite::TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA
            }
            Self::TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA => {
                CipherSuite::TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
            }
            Self::Grease => CipherSuite::TLS_RESERVED_GREASE,
        }
    }

    /// Converts the fingerprint cipher suite to rustls's SupportedCipherSuite.
    ///
    /// Returns `None` for advertise-only suites that have no aws-lc-rs
    /// implementation (e.g. legacy 3DES). These are still emitted in the
    /// ClientHello via [`Self::to_cipher_suite`] but cannot be negotiated.
    pub fn to_supported_cipher_suite(&self) -> Option<SupportedCipherSuite> {
        Some(match self {
            Self::TLS13_AES_128_GCM_SHA256 => aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256,
            Self::TLS13_AES_256_GCM_SHA384 => aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384,
            Self::TLS13_CHACHA20_POLY1305_SHA256 => {
                aws_lc_rs::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256
            }
            Self::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 => {
                aws_lc_rs::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            }
            Self::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 => {
                aws_lc_rs::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            }
            Self::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 => {
                aws_lc_rs::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            }
            Self::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => {
                aws_lc_rs::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
            }
            Self::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 => {
                aws_lc_rs::cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
            }
            Self::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => {
                aws_lc_rs::cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
            }
            Self::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA => {
                aws_lc_rs::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
            }
            Self::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA => {
                aws_lc_rs::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
            }
            Self::TLS_RSA_WITH_AES_128_GCM_SHA256 => {
                aws_lc_rs::cipher_suite::TLS_RSA_WITH_AES_128_GCM_SHA256
            }
            Self::TLS_RSA_WITH_AES_256_GCM_SHA384 => {
                aws_lc_rs::cipher_suite::TLS_RSA_WITH_AES_256_GCM_SHA384
            }
            Self::TLS_RSA_WITH_AES_128_CBC_SHA => {
                aws_lc_rs::cipher_suite::TLS_RSA_WITH_AES_128_CBC_SHA
            }
            Self::TLS_RSA_WITH_AES_256_CBC_SHA => {
                aws_lc_rs::cipher_suite::TLS_RSA_WITH_AES_256_CBC_SHA
            }
            Self::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA => {
                aws_lc_rs::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
            }
            Self::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA => {
                aws_lc_rs::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
            }
            Self::TLS_RSA_WITH_3DES_EDE_CBC_SHA
            | Self::TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA
            | Self::TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA => return None,
            Self::Grease => aws_lc_rs::cipher_suite::TLS13_RESERVED_GREASE,
        })
    }
}

/// Key exchange groups for fingerprinting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FingerprintKeyExchangeGroup {
    X25519,
    /// X25519 with MLKEM768 (post-quantum hybrid)
    X25519MLKEM768,
    Secp256r1,
    Secp384r1,
    Secp521r1,
    Ffdhe2048,
    Ffdhe3072,
    Ffdhe4096,
    Ffdhe6144,
    Ffdhe8192,
    /// GREASE key exchange group
    Grease,
}

impl FingerprintKeyExchangeGroup {
    /// Converts the fingerprint key exchange group to rustls's NamedGroup.
    pub fn to_named_group(&self) -> NamedGroup {
        match self {
            Self::X25519 => NamedGroup::X25519,
            Self::X25519MLKEM768 => NamedGroup::X25519MLKEM768,
            Self::Secp256r1 => NamedGroup::secp256r1,
            Self::Secp384r1 => NamedGroup::secp384r1,
            Self::Secp521r1 => NamedGroup::secp521r1,
            Self::Ffdhe2048 => NamedGroup::FFDHE2048,
            Self::Ffdhe3072 => NamedGroup::FFDHE3072,
            Self::Ffdhe4096 => NamedGroup::FFDHE4096,
            Self::Ffdhe6144 => NamedGroup::FFDHE6144,
            Self::Ffdhe8192 => NamedGroup::FFDHE8192,
            Self::Grease => NamedGroup::GREASE,
        }
    }
}

/// Signature algorithms for fingerprinting.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FingerprintSignatureAlgorithm {
    // ECDSA algorithms
    EcdsaSecp256r1Sha256,
    EcdsaSecp384r1Sha384,
    EcdsaSecp521r1Sha512,
    // RSA PSS algorithms
    RsaPssRsaSha256,
    RsaPssRsaSha384,
    RsaPssRsaSha512,
    // RSA PKCS#1 algorithms
    RsaPkcs1Sha256,
    RsaPkcs1Sha384,
    RsaPkcs1Sha512,
    RsaPkcs1Sha1,
    // EdDSA algorithms
    Ed25519,
    Ed448,
    // ML-DSA algorithms (draft-ietf-tls-mldsa)
    MlDsa44,
    MlDsa65,
    MlDsa87,
    // Legacy
    EcdsaSha1Legacy,
}

impl FingerprintSignatureAlgorithm {
    /// Converts the fingerprint signature algorithm to rustls's SignatureScheme.
    pub fn to_signature_scheme(&self) -> SignatureScheme {
        match self {
            Self::EcdsaSecp256r1Sha256 => SignatureScheme::ECDSA_NISTP256_SHA256,
            Self::EcdsaSecp384r1Sha384 => SignatureScheme::ECDSA_NISTP384_SHA384,
            Self::EcdsaSecp521r1Sha512 => SignatureScheme::ECDSA_NISTP521_SHA512,
            Self::RsaPssRsaSha256 => SignatureScheme::RSA_PSS_SHA256,
            Self::RsaPssRsaSha384 => SignatureScheme::RSA_PSS_SHA384,
            Self::RsaPssRsaSha512 => SignatureScheme::RSA_PSS_SHA512,
            Self::RsaPkcs1Sha256 => SignatureScheme::RSA_PKCS1_SHA256,
            Self::RsaPkcs1Sha384 => SignatureScheme::RSA_PKCS1_SHA384,
            Self::RsaPkcs1Sha512 => SignatureScheme::RSA_PKCS1_SHA512,
            Self::RsaPkcs1Sha1 => SignatureScheme::RSA_PKCS1_SHA1,
            Self::Ed25519 => SignatureScheme::ED25519,
            Self::Ed448 => SignatureScheme::ED448,
            Self::MlDsa44 => SignatureScheme::ML_DSA_44,
            Self::MlDsa65 => SignatureScheme::ML_DSA_65,
            Self::MlDsa87 => SignatureScheme::ML_DSA_87,
            Self::EcdsaSha1Legacy => SignatureScheme::ECDSA_SHA1_Legacy,
        }
    }
}

/// Certificate compression algorithms for fingerprinting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FingerprintCertCompressionAlgorithm {
    Zlib,
    Brotli,
    Zstd,
}

/// TLS extensions configuration for fingerprinting.
#[derive(Clone, Debug, Default)]
pub struct TlsExtensionsConfig {
    /// Whether to send GREASE extensions
    pub grease: bool,
    /// Whether to send signed_certificate_timestamp extension
    pub signed_certificate_timestamp: bool,
    /// Whether to send application_settings extension
    pub application_settings: bool,
    /// Whether to use new ALPS codepoint (17613) instead of old (17513)
    /// Chrome 136+ uses the new codepoint
    pub use_new_alps_codepoint: bool,
    /// Whether to send delegated_credentials extension
    pub delegated_credentials: bool,
    /// Whether to send record_size_limit extension
    pub record_size_limit: Option<u16>,
    /// Whether to send renegotiation_info extension
    pub renegotiation_info: bool,
    /// Whether to send padding extension (RFC7685)
    pub padding: bool,
    /// Whether to send supported_versions extension.
    /// Defaults to true. Set to false for TLS 1.2-only fingerprints (e.g.
    /// OkHttp 3) where the real client never advertises TLS 1.3 support.
    pub supported_versions: bool,
    /// Explicit extension order for fingerprinting.
    /// When non-empty, all listed extensions are emitted in this exact order
    /// via contiguous_extensions, bypassing randomization.
    pub extension_order: Vec<ExtensionType>,
}

/// Default signature verification algorithms.
/// Based on common browser implementations.
pub static DEFAULT_SIGNATURE_VERIFICATION_ALGOS: WebPkiSupportedAlgorithms =
    WebPkiSupportedAlgorithms {
        all: &[
            webpki_algs::ECDSA_P256_SHA256,
            webpki_algs::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
            webpki_algs::RSA_PKCS1_2048_8192_SHA256,
            webpki_algs::ECDSA_P384_SHA384,
            webpki_algs::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
            webpki_algs::RSA_PKCS1_2048_8192_SHA384,
            webpki_algs::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
            webpki_algs::RSA_PKCS1_2048_8192_SHA512,
        ],
        mapping: &[
            (
                SignatureScheme::ECDSA_NISTP256_SHA256,
                &[webpki_algs::ECDSA_P256_SHA256],
            ),
            (
                SignatureScheme::RSA_PSS_SHA256,
                &[webpki_algs::RSA_PSS_2048_8192_SHA256_LEGACY_KEY],
            ),
            (
                SignatureScheme::RSA_PKCS1_SHA256,
                &[webpki_algs::RSA_PKCS1_2048_8192_SHA256],
            ),
            (
                SignatureScheme::ECDSA_NISTP384_SHA384,
                &[webpki_algs::ECDSA_P384_SHA384],
            ),
            (
                SignatureScheme::RSA_PSS_SHA384,
                &[webpki_algs::RSA_PSS_2048_8192_SHA384_LEGACY_KEY],
            ),
            (
                SignatureScheme::RSA_PKCS1_SHA384,
                &[webpki_algs::RSA_PKCS1_2048_8192_SHA384],
            ),
            (
                SignatureScheme::RSA_PSS_SHA512,
                &[webpki_algs::RSA_PSS_2048_8192_SHA512_LEGACY_KEY],
            ),
            (
                SignatureScheme::RSA_PKCS1_SHA512,
                &[webpki_algs::RSA_PKCS1_2048_8192_SHA512],
            ),
        ],
    };

impl FingerprintSignatureAlgorithm {
    /// Returns the webpki signature verification algorithms for this fingerprint algorithm.
    /// Returns an empty slice for algorithms that are not supported for verification (e.g., Ed448).
    fn to_webpki_algs(&self) -> &'static [&'static dyn pki_types::SignatureVerificationAlgorithm] {
        // Static arrays for algorithms used in the 'all' list
        static ECDSA_P256_ALGS: &[&dyn pki_types::SignatureVerificationAlgorithm] = &[
            webpki_algs::ECDSA_P256_SHA256,
            webpki_algs::ECDSA_P256_SHA384,
        ];
        static ECDSA_P384_ALGS: &[&dyn pki_types::SignatureVerificationAlgorithm] = &[
            webpki_algs::ECDSA_P384_SHA256,
            webpki_algs::ECDSA_P384_SHA384,
        ];
        static ECDSA_P521_ALGS: &[&dyn pki_types::SignatureVerificationAlgorithm] = &[
            webpki_algs::ECDSA_P521_SHA256,
            webpki_algs::ECDSA_P521_SHA384,
            webpki_algs::ECDSA_P521_SHA512,
        ];
        static RSA_PSS_256_ALGS: &[&dyn pki_types::SignatureVerificationAlgorithm] =
            &[webpki_algs::RSA_PSS_2048_8192_SHA256_LEGACY_KEY];
        static RSA_PSS_384_ALGS: &[&dyn pki_types::SignatureVerificationAlgorithm] =
            &[webpki_algs::RSA_PSS_2048_8192_SHA384_LEGACY_KEY];
        static RSA_PSS_512_ALGS: &[&dyn pki_types::SignatureVerificationAlgorithm] =
            &[webpki_algs::RSA_PSS_2048_8192_SHA512_LEGACY_KEY];
        static RSA_PKCS1_256_ALGS: &[&dyn pki_types::SignatureVerificationAlgorithm] =
            &[webpki_algs::RSA_PKCS1_2048_8192_SHA256];
        static RSA_PKCS1_384_ALGS: &[&dyn pki_types::SignatureVerificationAlgorithm] = &[
            webpki_algs::RSA_PKCS1_2048_8192_SHA384,
            webpki_algs::RSA_PKCS1_3072_8192_SHA384,
        ];
        static RSA_PKCS1_512_ALGS: &[&dyn pki_types::SignatureVerificationAlgorithm] =
            &[webpki_algs::RSA_PKCS1_2048_8192_SHA512];
        static ED25519_ALGS: &[&dyn pki_types::SignatureVerificationAlgorithm] =
            &[webpki_algs::ED25519];
        static EMPTY: &[&dyn pki_types::SignatureVerificationAlgorithm] = &[];

        match self {
            Self::EcdsaSecp256r1Sha256 => ECDSA_P256_ALGS,
            Self::EcdsaSecp384r1Sha384 => ECDSA_P384_ALGS,
            Self::EcdsaSecp521r1Sha512 => ECDSA_P521_ALGS,
            Self::RsaPssRsaSha256 => RSA_PSS_256_ALGS,
            Self::RsaPssRsaSha384 => RSA_PSS_384_ALGS,
            Self::RsaPssRsaSha512 => RSA_PSS_512_ALGS,
            Self::RsaPkcs1Sha256 => RSA_PKCS1_256_ALGS,
            Self::RsaPkcs1Sha384 => RSA_PKCS1_384_ALGS,
            Self::RsaPkcs1Sha512 => RSA_PKCS1_512_ALGS,
            Self::Ed25519 => ED25519_ALGS,
            // Ed448 is not supported by webpki, SHA1 legacy uses fallback in mapping
            Self::Ed448 | Self::RsaPkcs1Sha1 | Self::EcdsaSha1Legacy => EMPTY,
            // ML-DSA is advertised to match browsers that offer it, but webpki has
            // no verifier for it, so it contributes nothing to certificate validation.
            Self::MlDsa44 | Self::MlDsa65 | Self::MlDsa87 => EMPTY,
        }
    }

    /// Returns the mapping entry for this algorithm (SignatureScheme -> webpki algs).
    fn to_mapping_entry(
        &self,
    ) -> Option<(
        SignatureScheme,
        &'static [&'static dyn pki_types::SignatureVerificationAlgorithm],
    )> {
        // Static arrays for each algorithm type - includes multiple curves for ECDSA
        static ECDSA_P256_MAPPING: &[&dyn pki_types::SignatureVerificationAlgorithm] = &[
            webpki_algs::ECDSA_P256_SHA256,
            webpki_algs::ECDSA_P384_SHA256,
            webpki_algs::ECDSA_P521_SHA256,
        ];
        static ECDSA_P384_MAPPING: &[&dyn pki_types::SignatureVerificationAlgorithm] = &[
            webpki_algs::ECDSA_P384_SHA384,
            webpki_algs::ECDSA_P256_SHA384,
            webpki_algs::ECDSA_P521_SHA384,
        ];
        static ECDSA_P521_MAPPING: &[&dyn pki_types::SignatureVerificationAlgorithm] =
            &[webpki_algs::ECDSA_P521_SHA512];
        static RSA_PSS_256: &[&dyn pki_types::SignatureVerificationAlgorithm] =
            &[webpki_algs::RSA_PSS_2048_8192_SHA256_LEGACY_KEY];
        static RSA_PSS_384: &[&dyn pki_types::SignatureVerificationAlgorithm] =
            &[webpki_algs::RSA_PSS_2048_8192_SHA384_LEGACY_KEY];
        static RSA_PSS_512: &[&dyn pki_types::SignatureVerificationAlgorithm] =
            &[webpki_algs::RSA_PSS_2048_8192_SHA512_LEGACY_KEY];
        static RSA_PKCS1_256: &[&dyn pki_types::SignatureVerificationAlgorithm] =
            &[webpki_algs::RSA_PKCS1_2048_8192_SHA256];
        static RSA_PKCS1_384: &[&dyn pki_types::SignatureVerificationAlgorithm] =
            &[webpki_algs::RSA_PKCS1_2048_8192_SHA384];
        static RSA_PKCS1_512: &[&dyn pki_types::SignatureVerificationAlgorithm] =
            &[webpki_algs::RSA_PKCS1_2048_8192_SHA512];
        // Legacy SHA1 algorithms fall back to SHA256 (fake signature scheme from the patch)
        static RSA_PKCS1_SHA1_FALLBACK: &[&dyn pki_types::SignatureVerificationAlgorithm] =
            &[webpki_algs::RSA_PKCS1_2048_8192_SHA256];
        static ECDSA_SHA1_FALLBACK: &[&dyn pki_types::SignatureVerificationAlgorithm] =
            &[webpki_algs::ECDSA_P256_SHA256];
        static ED25519: &[&dyn pki_types::SignatureVerificationAlgorithm] = &[webpki_algs::ED25519];
        // ML-DSA is advertised for fingerprint accuracy but webpki has no verifier
        // for it. The mapping doubles as the list of schemes we offer, so the entry
        // has to exist; it must also be non-empty, because the TLS 1.3 verify path
        // indexes the first element. This placeholder can never validate an ML-DSA
        // signature, so a server that actually selects one fails the handshake
        // cleanly instead of panicking.
        //
        // Ed25519 rather than a P-256 verifier: the placeholder does get run, so a
        // server whose certificate key matches it could have a CertificateVerify
        // mislabelled as ML-DSA accepted. Only the legitimate key holder can produce
        // such a signature, but P-256 is the common case for publicly-trusted server
        // certificates whereas Ed25519 is not issued by public CAs, so this keeps the
        // window as small as the fallback approach allows.
        static ML_DSA_FALLBACK: &[&dyn pki_types::SignatureVerificationAlgorithm] =
            &[webpki_algs::ED25519];

        match self {
            Self::EcdsaSecp256r1Sha256 => {
                Some((SignatureScheme::ECDSA_NISTP256_SHA256, ECDSA_P256_MAPPING))
            }
            Self::EcdsaSecp384r1Sha384 => {
                Some((SignatureScheme::ECDSA_NISTP384_SHA384, ECDSA_P384_MAPPING))
            }
            Self::EcdsaSecp521r1Sha512 => {
                Some((SignatureScheme::ECDSA_NISTP521_SHA512, ECDSA_P521_MAPPING))
            }
            Self::RsaPssRsaSha256 => Some((SignatureScheme::RSA_PSS_SHA256, RSA_PSS_256)),
            Self::RsaPssRsaSha384 => Some((SignatureScheme::RSA_PSS_SHA384, RSA_PSS_384)),
            Self::RsaPssRsaSha512 => Some((SignatureScheme::RSA_PSS_SHA512, RSA_PSS_512)),
            Self::RsaPkcs1Sha256 => Some((SignatureScheme::RSA_PKCS1_SHA256, RSA_PKCS1_256)),
            Self::RsaPkcs1Sha384 => Some((SignatureScheme::RSA_PKCS1_SHA384, RSA_PKCS1_384)),
            Self::RsaPkcs1Sha512 => Some((SignatureScheme::RSA_PKCS1_SHA512, RSA_PKCS1_512)),
            Self::RsaPkcs1Sha1 => Some((SignatureScheme::RSA_PKCS1_SHA1, RSA_PKCS1_SHA1_FALLBACK)),
            Self::EcdsaSha1Legacy => {
                Some((SignatureScheme::ECDSA_SHA1_Legacy, ECDSA_SHA1_FALLBACK))
            }
            Self::Ed25519 => Some((SignatureScheme::ED25519, ED25519)),
            // Ed448 is not supported
            Self::Ed448 => None,
            Self::MlDsa44 => Some((SignatureScheme::ML_DSA_44, ML_DSA_FALLBACK)),
            Self::MlDsa65 => Some((SignatureScheme::ML_DSA_65, ML_DSA_FALLBACK)),
            Self::MlDsa87 => Some((SignatureScheme::ML_DSA_87, ML_DSA_FALLBACK)),
        }
    }
}

/// Global cache for `WebPkiSupportedAlgorithms` to avoid memory leaks from repeated `Box::leak` calls.
/// Each unique signature algorithm configuration is only leaked once.
mod sig_alg_cache {
    use super::{FingerprintSignatureAlgorithm, WebPkiSupportedAlgorithms};
    use alloc::boxed::Box;
    use alloc::collections::BTreeSet;
    use alloc::vec::Vec;
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};

    static CACHE: OnceLock<
        Mutex<HashMap<Vec<FingerprintSignatureAlgorithm>, WebPkiSupportedAlgorithms>>,
    > = OnceLock::new();

    fn get_cache()
    -> &'static Mutex<HashMap<Vec<FingerprintSignatureAlgorithm>, WebPkiSupportedAlgorithms>> {
        CACHE.get_or_init(|| Mutex::new(HashMap::new()))
    }

    pub(super) fn get_or_create(
        signature_algorithms: &[FingerprintSignatureAlgorithm],
    ) -> WebPkiSupportedAlgorithms {
        let cache = get_cache();

        // Check if we already have this configuration cached
        {
            let guard = cache.lock().unwrap();
            if let Some(cached) = guard.get(signature_algorithms) {
                return *cached;
            }
        }

        // Build the algorithms (will leak, but only once per unique configuration)
        let algorithms = build_algorithms(signature_algorithms);

        // Store in cache
        {
            let mut guard = cache.lock().unwrap();
            // Double-check in case another thread added it while we were building
            if let Some(cached) = guard.get(signature_algorithms) {
                return *cached;
            }
            guard.insert(signature_algorithms.to_vec(), algorithms);
        }

        algorithms
    }

    fn build_algorithms(
        signature_algorithms: &[FingerprintSignatureAlgorithm],
    ) -> WebPkiSupportedAlgorithms {
        // Collect all unique webpki algorithms (using pointer address for dedup)
        let mut seen: BTreeSet<usize> = BTreeSet::new();
        let all_algs: Vec<&'static dyn pki_types::SignatureVerificationAlgorithm> =
            signature_algorithms
                .iter()
                .flat_map(|sa| sa.to_webpki_algs().iter().copied())
                .filter(|alg| {
                    let ptr: *const dyn pki_types::SignatureVerificationAlgorithm = *alg;
                    seen.insert(ptr as *const () as usize)
                })
                .collect();

        // Collect mapping entries in fingerprint order
        let mapping_entries: Vec<(
            crate::SignatureScheme,
            &'static [&'static dyn pki_types::SignatureVerificationAlgorithm],
        )> = signature_algorithms
            .iter()
            .filter_map(|sa| sa.to_mapping_entry())
            .collect();

        // Leak the vectors to get 'static references
        // This only happens once per unique configuration due to caching
        let all_static: &'static [&'static dyn pki_types::SignatureVerificationAlgorithm] =
            Box::leak(all_algs.into_boxed_slice());
        let mapping_static: &'static [(
            crate::SignatureScheme,
            &'static [&'static dyn pki_types::SignatureVerificationAlgorithm],
        )] = Box::leak(mapping_entries.into_boxed_slice());

        WebPkiSupportedAlgorithms {
            all: all_static,
            mapping: mapping_static,
        }
    }
}

impl TlsFingerprint {
    /// Builds a `WebPkiSupportedAlgorithms` from this fingerprint's signature algorithms.
    ///
    /// The order of algorithms in the mapping reflects the fingerprint's preference order,
    /// which is important for TLS fingerprinting.
    ///
    /// Results are cached globally to avoid memory leaks from repeated allocations.
    /// Each unique signature algorithm configuration is only allocated once.
    pub fn to_signature_verification_algorithms(&self) -> WebPkiSupportedAlgorithms {
        sig_alg_cache::get_or_create(&self.signature_algorithms)
    }
}
