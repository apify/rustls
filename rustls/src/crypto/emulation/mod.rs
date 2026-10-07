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
        static ML_DSA_44_ALGS: &[&dyn pki_types::SignatureVerificationAlgorithm] =
            &[webpki_algs::ML_DSA_44];
        static ML_DSA_65_ALGS: &[&dyn pki_types::SignatureVerificationAlgorithm] =
            &[webpki_algs::ML_DSA_65];
        static ML_DSA_87_ALGS: &[&dyn pki_types::SignatureVerificationAlgorithm] =
            &[webpki_algs::ML_DSA_87];
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
            Self::MlDsa44 => ML_DSA_44_ALGS,
            Self::MlDsa65 => ML_DSA_65_ALGS,
            Self::MlDsa87 => ML_DSA_87_ALGS,
            // Ed448 is not supported by webpki, SHA1 legacy uses fallback in mapping
            Self::Ed448 | Self::RsaPkcs1Sha1 | Self::EcdsaSha1Legacy => EMPTY,
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
        static ML_DSA_44: &[&dyn pki_types::SignatureVerificationAlgorithm] =
            &[webpki_algs::ML_DSA_44];
        static ML_DSA_65: &[&dyn pki_types::SignatureVerificationAlgorithm] =
            &[webpki_algs::ML_DSA_65];
        static ML_DSA_87: &[&dyn pki_types::SignatureVerificationAlgorithm] =
            &[webpki_algs::ML_DSA_87];

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
            Self::MlDsa44 => Some((SignatureScheme::ML_DSA_44, ML_DSA_44)),
            Self::MlDsa65 => Some((SignatureScheme::ML_DSA_65, ML_DSA_65)),
            Self::MlDsa87 => Some((SignatureScheme::ML_DSA_87, ML_DSA_87)),
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

#[cfg(test)]
mod tests {
    use alloc::boxed::Box;
    use alloc::vec;

    use pki_types::{CertificateDer, PrivateKeyDer, ServerName};
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa,
        KeyPair, KeyUsagePurpose,
    };

    use super::*;
    use crate::crypto::CryptoProvider;
    use crate::server::WantsServerCert;
    use crate::sign::{CertifiedKey, Signer, SigningKey, SingleCertAndKey};
    use crate::sync::Arc;
    use crate::version::TLS13;
    use crate::{
        CertificateError, ClientConfig, ClientConnection, ConfigBuilder, Connection, Error,
        RootCertStore, ServerConfig, ServerConnection, SignatureAlgorithm,
    };

    #[test]
    fn server_with_ml_dsa_certificate_is_accepted() {
        // Each level signs both the chain and the CertificateVerify, so every ML-DSA entry is
        // exercised for certificate validation and for handshake signatures.
        for (name, alg) in [
            ("ML-DSA-44", &rcgen::PKCS_ML_DSA_44),
            ("ML-DSA-65", &rcgen::PKCS_ML_DSA_65),
            ("ML-DSA-87", &rcgen::PKCS_ML_DSA_87),
        ] {
            let (roots, ee_cert, ee_key) = issue(alg, alg);

            let server_config = server_config_builder()
                .with_single_cert(vec![ee_cert], ee_key)
                .unwrap();

            if let Err(err) = handshake(client_config(roots), server_config) {
                panic!("{name}: {err:?}");
            }
        }
    }

    #[test]
    fn ed25519_signature_labelled_as_ml_dsa_is_rejected() {
        let (roots, ee_cert, ee_key) = issue(&rcgen::PKCS_ED25519, &rcgen::PKCS_ED25519);

        // A genuine Ed25519 key whose CertificateVerify claims to be ML-DSA-44.
        let ed25519 = aws_lc_rs::default_provider()
            .key_provider
            .load_private_key(ee_key)
            .unwrap();
        let key = Arc::new(MislabelledKey(ed25519));
        let server_config = server_config_builder().with_cert_resolver(Arc::new(
            SingleCertAndKey::from(CertifiedKey::new(vec![ee_cert], key)),
        ));

        let err = handshake(client_config(roots), server_config).unwrap_err();
        assert!(
            matches!(
                err,
                Error::InvalidCertificate(
                    CertificateError::UnsupportedSignatureAlgorithmForPublicKeyContext { .. }
                )
            ),
            "{err:?}"
        );
    }

    /// A fingerprint that, like Chrome 150+, offers ML-DSA ahead of the classical schemes.
    fn fingerprint() -> TlsFingerprint {
        TlsFingerprint::new(
            vec![FingerprintCipherSuite::TLS13_AES_128_GCM_SHA256],
            // P-256 rather than X25519: `fips` builds drop X25519 from the provider.
            vec![FingerprintKeyExchangeGroup::Secp256r1],
            vec![
                FingerprintSignatureAlgorithm::MlDsa44,
                FingerprintSignatureAlgorithm::MlDsa65,
                FingerprintSignatureAlgorithm::MlDsa87,
                FingerprintSignatureAlgorithm::EcdsaSecp256r1Sha256,
                FingerprintSignatureAlgorithm::Ed25519,
            ],
            TlsExtensionsConfig {
                supported_versions: true,
                ..TlsExtensionsConfig::default()
            },
            Vec::new(),
            None,
        )
    }

    /// Builds a client the way impit does: a provider derived from the fingerprint, which
    /// supplies the signature verification algorithms used by the certificate verifier.
    fn client_config(roots: RootCertStore) -> ClientConfig {
        let provider = CryptoProvider::builder()
            .with_tls_fingerprint(fingerprint())
            .build();
        ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_tls_fingerprint(fingerprint())
            .with_no_client_auth()
    }

    fn server_config_builder() -> ConfigBuilder<ServerConfig, WantsServerCert> {
        ServerConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
            .with_protocol_versions(&[&TLS13])
            .unwrap()
            .with_no_client_auth()
    }

    /// Issues a CA certificate and a `localhost` end-entity certificate signed by it.
    fn issue(
        ca_alg: &'static rcgen::SignatureAlgorithm,
        ee_alg: &'static rcgen::SignatureAlgorithm,
    ) -> (
        RootCertStore,
        CertificateDer<'static>,
        PrivateKeyDer<'static>,
    ) {
        let mut ca_params = CertificateParams::new(vec!["Test CA".into()]).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
        ];
        ca_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let issuer =
            CertifiedIssuer::self_signed(ca_params, KeyPair::generate_for(ca_alg).unwrap())
                .unwrap();

        let ee_key = KeyPair::generate_for(ee_alg).unwrap();
        let ee_cert = CertificateParams::new(vec!["localhost".into()])
            .unwrap()
            .signed_by(&ee_key, &issuer)
            .unwrap();

        let mut roots = RootCertStore::empty();
        roots.add(issuer.der().clone()).unwrap();
        (
            roots,
            ee_cert.der().clone(),
            PrivateKeyDer::try_from(ee_key.serialize_der()).unwrap(),
        )
    }

    /// Runs a handshake to completion, returning the first error either side reports.
    fn handshake(client_config: ClientConfig, server_config: ServerConfig) -> Result<(), Error> {
        let mut client = Connection::from(
            ClientConnection::new(
                Arc::new(client_config),
                ServerName::try_from("localhost").unwrap(),
            )
            .unwrap(),
        );
        let mut server = Connection::from(ServerConnection::new(Arc::new(server_config)).unwrap());

        while client.is_handshaking() || server.is_handshaking() {
            let client_sent = transfer(&mut client, &mut server)?;
            let server_sent = transfer(&mut server, &mut client)?;
            assert!(client_sent || server_sent, "handshake stalled");
        }
        Ok(())
    }

    /// Moves everything `from` has queued into `to`. ML-DSA flights are several kilobytes, more
    /// than a single `read_tls()` call accepts, so both directions loop until drained.
    fn transfer(from: &mut Connection, to: &mut Connection) -> Result<bool, Error> {
        let mut buf = Vec::new();
        while from.wants_write() {
            from.write_tls(&mut buf).unwrap();
        }

        let mut rd = &buf[..];
        while !rd.is_empty() {
            let read = to.read_tls(&mut rd).unwrap();
            assert_ne!(read, 0, "read_tls made no progress");
            to.process_new_packets()?;
        }
        Ok(!buf.is_empty())
    }

    /// Signs with an Ed25519 key but labels the signature as ML-DSA-44.
    #[derive(Debug)]
    struct MislabelledKey(Arc<dyn SigningKey>);

    impl SigningKey for MislabelledKey {
        fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
            if !offered.contains(&SignatureScheme::ML_DSA_44) {
                return None;
            }
            let inner = self
                .0
                .choose_scheme(&[SignatureScheme::ED25519])?;
            Some(Box::new(MislabelledSigner(inner)))
        }

        fn algorithm(&self) -> SignatureAlgorithm {
            self.0.algorithm()
        }
    }

    #[derive(Debug)]
    struct MislabelledSigner(Box<dyn Signer>);

    impl Signer for MislabelledSigner {
        fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
            self.0.sign(message)
        }

        fn scheme(&self) -> SignatureScheme {
            SignatureScheme::ML_DSA_44
        }
    }
}
