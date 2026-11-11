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
    /// GREASE signature algorithm. Advertise-only: sent in the ClientHello at its list
    /// position, never offered to the verifier.
    ///
    /// The value is fixed at `0x1a1a` (real Chrome draws one per connection), and only the
    /// first `Grease` in the list is sent.
    Grease,
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
            Self::Grease => SignatureScheme::Unknown(0x1a1a),
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
    /// Send Chrome's two GREASE extensions: `0xbaba` with an empty body first, and `0xaaaa` with
    /// body `00` last (before padding and `pre_shared_key`). The rest of the order is unchanged.
    pub grease_first_and_last: bool,
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
    /// Trust Anchor IDs (draft-ietf-tls-trust-anchor-ids, Chrome's codepoint `0xca34`) to
    /// advertise, each 1-32 bytes; `None` sends nothing.
    pub trust_anchors: Option<Vec<Vec<u8>>>,
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
            // GREASE has nothing to verify
            Self::Grease => EMPTY,
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
            // Never in the mapping: an entry with no algorithms would make
            // `verify_tls13_signature` panic on a server that picks GREASE.
            Self::Grease => None,
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

    /// The number of entries before the first `Grease` whose scheme is in `sent`, the
    /// ClientHello's `signature_algorithms`, or `None` if the fingerprint doesn't list GREASE.
    ///
    /// With the fingerprint's own verifier this never exceeds `sent.len()`: `sent` is the
    /// fingerprint's order with entries removed (those without a mapping, and those upstream's
    /// TLS 1.2 filter drops). With another verifier's list (e.g. `NoVerifier`) it may, and the
    /// caller clamps.
    pub(crate) fn signature_algorithm_grease_position(
        &self,
        sent: &[SignatureScheme],
    ) -> Option<usize> {
        let grease = self
            .signature_algorithms
            .iter()
            .position(|sa| *sa == FingerprintSignatureAlgorithm::Grease)?;
        Some(
            self.signature_algorithms[..grease]
                .iter()
                .filter(|sa| sent.contains(&sa.to_signature_scheme()))
                .count(),
        )
    }
}

#[cfg(test)]
mod tests {
    use alloc::boxed::Box;
    use alloc::vec;
    use std::sync::Mutex;

    use pki_types::{CertificateDer, DnsName, EchConfigListBytes, PrivateKeyDer, ServerName};
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa,
        KeyPair, KeyUsagePurpose,
    };

    use super::*;
    use crate::client::{EchConfig, EchGreaseConfig, EchMode};
    use crate::crypto::CryptoProvider;
    use crate::crypto::aws_lc_rs::hpke::DH_KEM_P256_HKDF_SHA256_AES_128;
    use crate::crypto::hpke::Hpke;
    use crate::msgs::base::PayloadU16;
    use crate::msgs::codec::Codec;
    use crate::msgs::handshake::{EchConfigContents, EchConfigPayload, HpkeKeyConfig};
    #[cfg(feature = "tls12")]
    use crate::server::Acceptor;
    use crate::server::{ClientHello, ResolvesServerCert, WantsServerCert};
    use crate::sign::{CertifiedKey, Signer, SigningKey, SingleCertAndKey};
    use crate::sync::Arc;
    use crate::verify::{DigitallySignedStruct, NoVerifier};
    #[cfg(feature = "tls12")]
    use crate::version::TLS12;
    use crate::version::TLS13;
    use crate::{
        CertificateError, ClientConfig, ClientConnection, ConfigBuilder, Connection, Error,
        PeerMisbehaved, RootCertStore, ServerConfig, ServerConnection, SignatureAlgorithm,
        SupportedProtocolVersion,
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
        client_config_with(fingerprint(), roots)
    }

    /// Like `client_config`, for an arbitrary fingerprint (set on both the provider and the config).
    fn client_config_with(fp: TlsFingerprint, roots: RootCertStore) -> ClientConfig {
        client_config_for(fp, roots, &[&TLS13])
    }

    /// Like `client_config_with`, offering only `versions`.
    fn client_config_for(
        fp: TlsFingerprint,
        roots: RootCertStore,
        versions: &[&'static SupportedProtocolVersion],
    ) -> ClientConfig {
        let provider = CryptoProvider::builder()
            .with_tls_fingerprint(fp.clone())
            .build();
        ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(versions)
            .unwrap()
            .with_root_certificates(roots)
            .with_tls_fingerprint(fp)
            .with_no_client_auth()
    }

    /// The ClientHello extensions `fp` produces, as (type, body) in wire order.
    fn client_hello_extensions(fp: TlsFingerprint) -> Vec<(u16, Vec<u8>)> {
        hello_extensions(client_config_with(fp, RootCertStore::empty()))
    }

    /// The ClientHello extensions `config` produces, as (type, body) in wire order.
    fn hello_extensions(config: ClientConfig) -> Vec<(u16, Vec<u8>)> {
        let mut conn =
            ClientConnection::new(Arc::new(config), ServerName::try_from("localhost").unwrap())
                .unwrap();
        let mut record = Vec::new();
        conn.write_tls(&mut record).unwrap();

        // Skip the record (5) and handshake (4) headers.
        extensions_of(&record[9..])
    }

    /// A ClientHello's extensions, as (type, body) in wire order.
    type Extensions = Vec<(u16, Vec<u8>)>;

    /// The extensions of a ClientHello body (after the handshake header).
    fn extensions_of(hello: &[u8]) -> Extensions {
        let u16_at = |i: usize| usize::from(u16::from_be_bytes([hello[i], hello[i + 1]]));
        let mut i = 2 + 32; // legacy_version, random
        i += 1 + usize::from(hello[i]); // legacy_session_id
        i += 2 + u16_at(i); // cipher_suites
        i += 1 + usize::from(hello[i]); // legacy_compression_methods
        let end = i + 2 + u16_at(i);
        i += 2;
        let mut extensions = Vec::new();
        while i < end {
            let body_end = i + 4 + u16_at(i + 2);
            extensions.push((u16_at(i) as u16, hello[i + 4..body_end].to_vec()));
            i = body_end;
        }
        assert_eq!(i, end, "ClientHello extensions not parsed");
        extensions
    }

    /// Chrome 155's Trust Anchor IDs extension body: 28 IDs.
    const CHROME_155_TRUST_ANCHORS: &str = "00b80582df1302010582df1302060582df13020d0582df13020e0582df13020f0582df1302120582df1302130582df13021408839a648c9b2d010708839a648c9b2d010808839a648c9b2d010908839a648c9b2d010a08839a648c9b2d010b08839a648c9b2d010c08839a648c9b2d010d08839a648c9b2d011208839a648c9b2d011304d679090104d679090404d679090504d679090604d679090704d679090804d679090a04d679090b04d679090c04d679090d04d679090f";

    /// Splits a RequestedTrustAnchorList (u16 length, then u8-prefixed IDs) into its IDs.
    fn chrome_28_ids() -> Vec<Vec<u8>> {
        let body = hex::decode(CHROME_155_TRUST_ANCHORS).unwrap();
        let mut ids = Vec::new();
        let mut rest = &body[2..];
        while let Some((&len, tail)) = rest.split_first() {
            let (id, tail) = tail.split_at(usize::from(len));
            ids.push(id.to_vec());
            rest = tail;
        }
        ids
    }

    #[test]
    fn trust_anchor_ids_are_encoded_like_chrome() {
        let mut fp = fingerprint();
        fp.extensions.trust_anchors = Some(chrome_28_ids());
        assert_eq!(chrome_28_ids().len(), 28);
        let exts = client_hello_extensions(fp);
        let body = exts
            .iter()
            .find(|(t, _)| *t == 0xca34)
            .map(|(_, b)| b.clone());
        assert_eq!(body, Some(hex::decode(CHROME_155_TRUST_ANCHORS).unwrap()));
    }

    #[test]
    fn empty_trust_anchor_list_is_encoded_as_empty() {
        let mut fp = fingerprint();
        fp.extensions.trust_anchors = Some(Vec::new());
        let exts = client_hello_extensions(fp);
        let body = exts
            .iter()
            .find(|(t, _)| *t == 0xca34)
            .map(|(_, b)| b.clone());
        assert_eq!(body, Some(vec![0, 0]));
    }

    #[test]
    fn trust_anchor_ids_are_not_sent_unless_configured() {
        assert!(
            !client_hello_extensions(fingerprint())
                .iter()
                .any(|(t, _)| *t == 0xca34)
        );
    }

    /// `fp` with Chrome's two GREASE extensions turned on.
    fn greased(mut fp: TlsFingerprint) -> TlsFingerprint {
        fp.extensions.grease_first_and_last = true;
        fp
    }

    /// The types of `exts`, in order, asserting that none occurs twice.
    fn distinct_types(exts: &[(u16, Vec<u8>)]) -> Vec<u16> {
        let types: Vec<u16> = exts.iter().map(|(t, _)| *t).collect();
        for (i, t) in types.iter().enumerate() {
            assert!(
                !types[i + 1..].contains(t),
                "{t:#06x} twice in {types:04x?}"
            );
        }
        types
    }

    /// Asserts that `exts` starts with the empty GREASE extension, ends with the one-byte one,
    /// and has no type twice.
    fn assert_grease_first_and_last(exts: &[(u16, Vec<u8>)]) {
        distinct_types(exts);
        assert_eq!(exts[0], (0xbaba, vec![]));
        assert_eq!(*exts.last().unwrap(), (0xaaaa, vec![0]));
    }

    #[test]
    fn grease_extensions_go_first_and_last() {
        assert_grease_first_and_last(&client_hello_extensions(greased(fingerprint())));
    }

    #[test]
    fn grease_extensions_are_not_sent_unless_configured() {
        let types = distinct_types(&client_hello_extensions(fingerprint()));
        assert!(!types.contains(&0xbaba), "{types:04x?}");
        assert!(!types.contains(&0xaaaa), "{types:04x?}");
    }

    #[test]
    fn listed_grease_is_sent_once_and_first() {
        let mut fp = greased(fingerprint());
        fp.extensions.grease = true;
        fp.extensions.extension_order = vec![
            ExtensionType::SupportedVersions,
            ExtensionType::ReservedGrease,
            ExtensionType::KeyShare,
        ];
        let exts = client_hello_extensions(fp);
        assert_grease_first_and_last(&exts);

        // The rest of the listed order stays as it was.
        let types = distinct_types(&exts);
        assert!(
            types
                .windows(2)
                .any(|pair| pair == [0x002b, 0x0033]),
            "{types:04x?}"
        );
    }

    #[test]
    fn padding_follows_the_last_grease_extension() {
        let mut fp = greased(fingerprint());
        fp.extensions.padding = true;
        let exts = client_hello_extensions(fp);
        distinct_types(&exts);
        assert_eq!(exts[0], (0xbaba, vec![]));
        assert_eq!(
            exts[exts.len() - 2..],
            [(0xaaaa, vec![0]), (0x0015, vec![])]
        );
    }

    /// A client for `fp` that sends ECH as `ech_mode` says.
    fn client_config_with_ech(fp: TlsFingerprint, ech_mode: EchMode) -> ClientConfig {
        let provider = CryptoProvider::builder()
            .with_tls_fingerprint(fp.clone())
            .build();
        ClientConfig::builder_with_provider(Arc::new(provider))
            .with_ech(ech_mode)
            .unwrap()
            .with_root_certificates(RootCertStore::empty())
            .with_tls_fingerprint(fp)
            .with_no_client_auth()
    }

    // ECH uses P-256 HPKE, not impit's X25519: `fips` builds have no X25519 HPKE suites.
    static ECH_SUITE: &dyn Hpke = DH_KEM_P256_HKDF_SHA256_AES_128;

    #[test]
    fn last_grease_extension_follows_grease_ech() {
        let (public_key, _) = ECH_SUITE.generate_key_pair().unwrap();
        let ech_mode = EchMode::Grease(EchGreaseConfig::new(ECH_SUITE, public_key));
        let exts = hello_extensions(client_config_with_ech(greased(fingerprint()), ech_mode));
        assert_grease_first_and_last(&exts);

        let types = distinct_types(&exts);
        assert_eq!(types[types.len() - 2..], [0xfe0d, 0xaaaa]);
    }

    #[test]
    fn real_ech_hello_keeps_grease_first_and_last() {
        // An ECHConfigList with one config, as a server would publish it.
        let (public_key, _) = ECH_SUITE.generate_key_pair().unwrap();
        let config = EchConfigPayload::V18(EchConfigContents {
            key_config: HpkeKeyConfig {
                config_id: 7,
                kem_id: ECH_SUITE.suite().kem,
                public_key: PayloadU16::new(public_key.0),
                symmetric_cipher_suites: vec![ECH_SUITE.suite().sym],
            },
            maximum_name_length: 0,
            public_name: DnsName::try_from("public.example").unwrap(),
            extensions: Vec::new(),
        });
        let config_list = EchConfigListBytes::from(vec![config].get_encoding());
        let ech_mode = EchMode::Enable(EchConfig::new(config_list, &[ECH_SUITE]).unwrap());

        let exts = hello_extensions(client_config_with_ech(greased(fingerprint()), ech_mode));
        assert_grease_first_and_last(&exts);

        let types = distinct_types(&exts);
        assert_eq!(types[types.len() - 2..], [0xfe0d, 0xaaaa]);
    }

    #[test]
    fn pre_shared_key_stays_last_after_grease() {
        let (roots, ee_cert, ee_key) = issue(
            &rcgen::PKCS_ECDSA_P256_SHA256,
            &rcgen::PKCS_ECDSA_P256_SHA256,
        );
        let server_config = server_config_builder()
            .with_single_cert(vec![ee_cert], ee_key)
            .unwrap();
        let config = client_config_with(greased(fingerprint()), roots);

        // The first handshake leaves a ticket in the session store that `config` shares.
        handshake(config.clone(), server_config).unwrap();

        let exts = hello_extensions(config);
        assert_eq!(exts[0], (0xbaba, vec![]));
        let types = distinct_types(&exts);
        assert_eq!(types[types.len() - 2..], [0xaaaa, 0x0029]);
    }

    /// `fingerprint()` plus what Chrome 152+ adds: GREASE first in `signature_algorithms`, Trust
    /// Anchor IDs, and the two GREASE extensions.
    fn chrome_152_fingerprint() -> TlsFingerprint {
        let mut fp = fingerprint();
        fp.signature_algorithms = vec![
            FingerprintSignatureAlgorithm::Grease,
            FingerprintSignatureAlgorithm::EcdsaSecp256r1Sha256,
            FingerprintSignatureAlgorithm::RsaPssRsaSha256,
        ];
        fp.extensions.trust_anchors = Some(chrome_28_ids());
        greased(fp)
    }

    /// The `signature_algorithms` extension body `fp` sends.
    fn sent_signature_algorithms(fp: TlsFingerprint) -> Option<Vec<u8>> {
        signature_algorithms_sent_by(client_config_with(fp, RootCertStore::empty()))
    }

    /// The `signature_algorithms` extension body `config` sends.
    fn signature_algorithms_sent_by(config: ClientConfig) -> Option<Vec<u8>> {
        hello_extensions(config)
            .into_iter()
            .find(|(t, _)| *t == 0x000d)
            .map(|(_, body)| body)
    }

    /// `fingerprint()` with `signature_algorithms` and a single TLS 1.2 suite, so that upstream's
    /// filter of TLS-1.3-only signature schemes applies.
    ///
    /// Exactly one suite: the GREASE suite, and the ECDHE CBC and static-RSA suites, are fake
    /// TLS 1.3 suites in this fork, so listing any of them would switch the filter off.
    #[cfg(feature = "tls12")]
    fn tls12_fingerprint(
        signature_algorithms: Vec<FingerprintSignatureAlgorithm>,
    ) -> TlsFingerprint {
        let mut fp = fingerprint();
        fp.cipher_suites = vec![FingerprintCipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256];
        fp.signature_algorithms = signature_algorithms;
        fp
    }

    /// A client for a `tls12_fingerprint`. It offers TLS 1.2 only: its provider has no TLS 1.3
    /// suite, so a TLS 1.3 client can't be built from it.
    #[cfg(feature = "tls12")]
    fn tls12_client_config(fp: TlsFingerprint, roots: RootCertStore) -> ClientConfig {
        client_config_for(fp, roots, &[&TLS12])
    }

    #[test]
    fn grease_signature_algorithm_is_sent_in_place() {
        assert_eq!(
            sent_signature_algorithms(chrome_152_fingerprint()),
            Some(vec![0x00, 0x06, 0x1a, 0x1a, 0x04, 0x03, 0x08, 0x04])
        );

        // Ed448 never reaches the wire, so it doesn't count towards GREASE's position.
        let mut fp = fingerprint();
        fp.signature_algorithms = vec![
            FingerprintSignatureAlgorithm::Ed448,
            FingerprintSignatureAlgorithm::Grease,
            FingerprintSignatureAlgorithm::EcdsaSecp256r1Sha256,
        ];
        assert_eq!(
            sent_signature_algorithms(fp),
            Some(vec![0x00, 0x04, 0x1a, 0x1a, 0x04, 0x03])
        );

        // Only the entries that are sent count: ECDSA does, Ed448 doesn't.
        let mut fp = fingerprint();
        fp.signature_algorithms = vec![
            FingerprintSignatureAlgorithm::EcdsaSecp256r1Sha256,
            FingerprintSignatureAlgorithm::Ed448,
            FingerprintSignatureAlgorithm::Grease,
            FingerprintSignatureAlgorithm::RsaPssRsaSha256,
        ];
        assert_eq!(
            sent_signature_algorithms(fp),
            Some(vec![0x00, 0x06, 0x04, 0x03, 0x1a, 0x1a, 0x08, 0x04])
        );
    }

    #[cfg(feature = "tls12")]
    #[test]
    fn grease_signature_algorithm_survives_tls12_only_suites() {
        let fp = tls12_fingerprint(vec![
            FingerprintSignatureAlgorithm::Grease,
            FingerprintSignatureAlgorithm::EcdsaSecp256r1Sha256,
            FingerprintSignatureAlgorithm::RsaPssRsaSha256,
        ]);
        assert_eq!(
            signature_algorithms_sent_by(tls12_client_config(fp, RootCertStore::empty())),
            Some(vec![0x00, 0x06, 0x1a, 0x1a, 0x04, 0x03, 0x08, 0x04])
        );
    }

    #[cfg(feature = "tls12")]
    #[test]
    fn tls12_only_grease_position_skips_filtered_schemes() {
        // Upstream's filter drops ML-DSA, so it doesn't count towards GREASE's position.
        let fp = tls12_fingerprint(vec![
            FingerprintSignatureAlgorithm::MlDsa44,
            FingerprintSignatureAlgorithm::Grease,
            FingerprintSignatureAlgorithm::EcdsaSecp256r1Sha256,
        ]);
        assert_eq!(
            signature_algorithms_sent_by(tls12_client_config(fp, RootCertStore::empty())),
            Some(vec![0x00, 0x04, 0x1a, 0x1a, 0x04, 0x03])
        );
    }

    #[test]
    fn grease_position_with_no_verifier_list() {
        // With `ignore_tls_errors`, impit swaps in NoVerifier, whose fixed list isn't built from
        // the fingerprint. GREASE's position is counted over that list.
        let sent_with_no_verifier = |signature_algorithms| {
            let mut fp = fingerprint();
            fp.signature_algorithms = signature_algorithms;
            let mut config = client_config_with(fp, RootCertStore::empty());
            config
                .dangerous()
                .set_certificate_verifier(Arc::new(NoVerifier::with_default_schemes()));
            signature_algorithms_sent_by(config)
        };

        assert_eq!(
            sent_with_no_verifier(vec![
                FingerprintSignatureAlgorithm::Grease,
                FingerprintSignatureAlgorithm::EcdsaSecp256r1Sha256,
                FingerprintSignatureAlgorithm::RsaPssRsaSha256,
            ]),
            Some(vec![
                0x00, 0x1c, 0x1a, 0x1a, 0x02, 0x01, 0x02, 0x03, 0x04, 0x01, 0x04, 0x03, 0x05, 0x01,
                0x05, 0x03, 0x06, 0x01, 0x06, 0x03, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06, 0x08, 0x07,
                0x08, 0x08,
            ])
        );

        // The count, 14, passes NoVerifier's 13 entries, so the clamp puts GREASE last.
        let mut signature_algorithms =
            vec![FingerprintSignatureAlgorithm::EcdsaSecp256r1Sha256; 14];
        signature_algorithms.push(FingerprintSignatureAlgorithm::Grease);
        assert_eq!(
            sent_with_no_verifier(signature_algorithms),
            Some(vec![
                0x00, 0x1c, 0x02, 0x01, 0x02, 0x03, 0x04, 0x01, 0x04, 0x03, 0x05, 0x01, 0x05, 0x03,
                0x06, 0x01, 0x06, 0x03, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06, 0x08, 0x07, 0x08, 0x08,
                0x1a, 0x1a,
            ])
        );

        // Ed448 is in NoVerifier's list, so it counts and GREASE goes at index 1.
        assert_eq!(
            sent_with_no_verifier(vec![
                FingerprintSignatureAlgorithm::Ed448,
                FingerprintSignatureAlgorithm::Grease,
                FingerprintSignatureAlgorithm::EcdsaSecp256r1Sha256,
            ]),
            Some(vec![
                0x00, 0x1c, 0x02, 0x01, 0x1a, 0x1a, 0x02, 0x03, 0x04, 0x01, 0x04, 0x03, 0x05, 0x01,
                0x05, 0x03, 0x06, 0x01, 0x06, 0x03, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06, 0x08, 0x07,
                0x08, 0x08,
            ])
        );
    }

    #[test]
    fn grease_signature_algorithm_is_not_verifiable() {
        let algs = chrome_152_fingerprint().to_signature_verification_algorithms();
        assert_eq!(
            algs.supported_schemes(),
            vec![
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::RSA_PSS_SHA256
            ]
        );

        // A CertificateVerify that claims the GREASE value is refused, without a panic.
        let (_, ee_cert, _) = issue(
            &rcgen::PKCS_ECDSA_P256_SHA256,
            &rcgen::PKCS_ECDSA_P256_SHA256,
        );
        let dss = DigitallySignedStruct::new(SignatureScheme::Unknown(0x1a1a), vec![0; 64]);
        let err =
            crate::crypto::verify_tls13_signature(b"message", &ee_cert, &dss, &algs).unwrap_err();
        assert_eq!(
            err,
            Error::PeerMisbehaved(PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme)
        );
    }

    #[test]
    fn handshake_with_trust_anchors_and_grease_sigalg_succeeds() {
        let (roots, ee_cert, ee_key) = issue(
            &rcgen::PKCS_ECDSA_P256_SHA256,
            &rcgen::PKCS_ECDSA_P256_SHA256,
        );
        let server_config = server_config_builder()
            .with_single_cert(vec![ee_cert], ee_key)
            .unwrap();

        handshake(
            client_config_with(chrome_152_fingerprint(), roots),
            server_config,
        )
        .unwrap();
    }

    #[test]
    fn handshake_after_hello_retry_keeps_one_copy_of_each() {
        // The client's key share is P-256, which this server can't use, so it asks for P-384.
        let mut fp = chrome_152_fingerprint();
        fp.key_exchange_groups = vec![
            FingerprintKeyExchangeGroup::Secp256r1,
            FingerprintKeyExchangeGroup::Secp384r1,
        ];
        let (roots, ee_cert, ee_key) = issue(
            &rcgen::PKCS_ECDSA_P256_SHA256,
            &rcgen::PKCS_ECDSA_P256_SHA256,
        );
        let ee_key = aws_lc_rs::default_provider()
            .key_provider
            .load_private_key(ee_key)
            .unwrap();
        let resolver = Arc::new(RecordSignatureSchemes {
            key: Arc::new(CertifiedKey::new(vec![ee_cert], ee_key)),
            seen: Mutex::default(),
        });
        let p384_only = CryptoProvider {
            kx_groups: vec![aws_lc_rs::kx_group::SECP384R1],
            ..aws_lc_rs::default_provider()
        };
        let server_config = ServerConfig::builder_with_provider(Arc::new(p384_only))
            .with_protocol_versions(&[&TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(resolver.clone());

        // The server rejects a ClientHello that repeats an extension, and the loop below checks
        // that each one carries `trust_anchors`, so the retried ClientHello has it exactly once.
        // It is there because `emit_client_hello_for_retry` rebuilds the extensions from the same
        // config.
        let hellos =
            handshake_recording_hellos(client_config_with(fp, roots), server_config).unwrap();

        // Two ClientHellos (so the server did retry), each with GREASE once, in its place.
        let sent = vec![
            SignatureScheme::Unknown(0x1a1a),
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PSS_SHA256,
        ];
        assert_eq!(*resolver.seen.lock().unwrap(), vec![sent.clone(), sent]);

        // Both start with the empty GREASE extension, end with the one-byte one and carry
        // `trust_anchors`.
        assert_eq!(hellos.len(), 2);
        for exts in &hellos {
            assert_grease_first_and_last(exts);
            assert!(
                exts.iter().any(|(t, _)| *t == 0xca34),
                "a ClientHello lacks trust_anchors"
            );
        }
    }

    #[cfg(feature = "tls12")]
    #[test]
    fn tls12_handshake_with_grease_sigalg_succeeds() {
        let fp = tls12_fingerprint(vec![
            FingerprintSignatureAlgorithm::Grease,
            FingerprintSignatureAlgorithm::EcdsaSecp256r1Sha256,
            FingerprintSignatureAlgorithm::RsaPssRsaSha256,
        ]);
        let (roots, ee_cert, ee_key) = issue(
            &rcgen::PKCS_ECDSA_P256_SHA256,
            &rcgen::PKCS_ECDSA_P256_SHA256,
        );
        let server_config =
            ServerConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
                .with_protocol_versions(&[&TLS12])
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(vec![ee_cert], ee_key)
                .unwrap();

        // Not `RecordSignatureSchemes`: before calling the cert resolver, the server drops the
        // schemes that don't suit the shared suites (here GREASE and RSA-PSS).
        let received =
            handshake_through_acceptor(tls12_client_config(fp, roots), server_config).unwrap();

        // One list, not one per hello: the `Acceptor` sees only the first ClientHello.
        assert_eq!(
            received,
            vec![
                SignatureScheme::Unknown(0x1a1a),
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::RSA_PSS_SHA256,
            ]
        );
    }

    /// Serves one certificate, recording the `signature_algorithms` of each ClientHello.
    #[derive(Debug)]
    struct RecordSignatureSchemes {
        key: Arc<CertifiedKey>,
        seen: Mutex<Vec<Vec<SignatureScheme>>>,
    }

    impl ResolvesServerCert for RecordSignatureSchemes {
        fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
            self.seen.lock().unwrap().push(
                client_hello
                    .signature_schemes()
                    .to_vec(),
            );
            Some(self.key.clone())
        }
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
        handshake_recording_hellos(client_config, server_config).map(|_| ())
    }

    /// Like `handshake`, returning the extensions of each ClientHello the client sent.
    fn handshake_recording_hellos(
        client_config: ClientConfig,
        server_config: ServerConfig,
    ) -> Result<Vec<Extensions>, Error> {
        let mut client = Connection::from(
            ClientConnection::new(
                Arc::new(client_config),
                ServerName::try_from("localhost").unwrap(),
            )
            .unwrap(),
        );
        let mut server = Connection::from(ServerConnection::new(Arc::new(server_config)).unwrap());
        let client_flights = finish_handshake_recording(&mut client, &mut server)?;

        // Each ClientHello is a plaintext handshake record (22) of its own, holding a ClientHello
        // message (1); skip the record (5) and handshake (4) headers.
        let mut hellos = Vec::new();
        for flight in client_flights {
            let mut rest = &flight[..];
            while !rest.is_empty() {
                let len = usize::from(u16::from_be_bytes([rest[3], rest[4]]));
                let (record, tail) = rest.split_at(5 + len);
                if record[0] == 22 && record[5] == 1 {
                    hellos.push(extensions_of(&record[9..]));
                }
                rest = tail;
            }
        }
        Ok(hellos)
    }

    /// Like `handshake`, with the server started from an `Acceptor`. Returns the signature schemes
    /// of the ClientHello as the server received it.
    #[cfg(feature = "tls12")]
    fn handshake_through_acceptor(
        client_config: ClientConfig,
        server_config: ServerConfig,
    ) -> Result<Vec<SignatureScheme>, Error> {
        let mut client = Connection::from(
            ClientConnection::new(
                Arc::new(client_config),
                ServerName::try_from("localhost").unwrap(),
            )
            .unwrap(),
        );

        let mut buf = Vec::new();
        while client.wants_write() {
            client.write_tls(&mut buf).unwrap();
        }
        let mut acceptor = Acceptor::default();
        let mut rd = &buf[..];
        while !rd.is_empty() {
            let read = acceptor.read_tls(&mut rd).unwrap();
            assert_ne!(read, 0, "read_tls made no progress");
        }
        let accepted = acceptor
            .accept()
            .map_err(|(err, _)| err)?
            .expect("ClientHello incomplete");
        let received = accepted
            .client_hello()
            .signature_schemes()
            .to_vec();

        let mut server = Connection::from(
            accepted
                .into_connection(Arc::new(server_config))
                .map_err(|(err, _)| err)?,
        );
        finish_handshake(&mut client, &mut server)?;
        Ok(received)
    }

    /// Exchanges flights until neither side is handshaking.
    fn finish_handshake(client: &mut Connection, server: &mut Connection) -> Result<(), Error> {
        finish_handshake_recording(client, server).map(|_| ())
    }

    /// Like `finish_handshake`, returning the TLS records of each flight the client sent.
    fn finish_handshake_recording(
        client: &mut Connection,
        server: &mut Connection,
    ) -> Result<Vec<Vec<u8>>, Error> {
        let mut client_flights = Vec::new();
        while client.is_handshaking() || server.is_handshaking() {
            let client_flight = transfer(client, server)?;
            let server_flight = transfer(server, client)?;
            assert!(
                !client_flight.is_empty() || !server_flight.is_empty(),
                "handshake stalled"
            );
            client_flights.push(client_flight);
        }
        Ok(client_flights)
    }

    /// Moves everything `from` has queued into `to`, returning it. ML-DSA flights are several
    /// kilobytes, more than a single `read_tls()` call accepts, so both directions loop until
    /// drained.
    fn transfer(from: &mut Connection, to: &mut Connection) -> Result<Vec<u8>, Error> {
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
        Ok(buf)
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
