#![cfg(feature = "impit")]
use crate::Tls12CipherSuite;
use crate::Tls13CipherSuite;
use crate::enums::SignatureScheme;

use super::{WebPkiSupportedAlgorithms, aws_lc_rs};
use webpki::aws_lc_rs as webpki_algs_aws;

/// The cipher suites supported by Google Chrome.
/// Note that some of these are not real cipher suites and their implementation doesn't match the specification.
pub static CHROME_TLS13_CIPHER_SUITES: [&Tls13CipherSuite; 10] = [
    aws_lc_rs::cipher_suite::TLS13_RESERVED_GREASE, // fake cipher suite from the patch
    aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256,
    aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384,
    aws_lc_rs::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
    aws_lc_rs::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, // fake cipher suite from the patch
    aws_lc_rs::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, // fake cipher suite from the patch
    aws_lc_rs::cipher_suite::TLS_RSA_WITH_AES_128_GCM_SHA256,    // fake cipher suite from the patch
    aws_lc_rs::cipher_suite::TLS_RSA_WITH_AES_256_GCM_SHA384,    // fake cipher suite from the patch
    aws_lc_rs::cipher_suite::TLS_RSA_WITH_AES_128_CBC_SHA,       // fake cipher suite from the patch
    aws_lc_rs::cipher_suite::TLS_RSA_WITH_AES_256_CBC_SHA,       // fake cipher suite from the patch
];

/// The TLS 1.2 cipher suites supported by Google Chrome.
pub static CHROME_TLS12_CIPHER_SUITES: [&Tls12CipherSuite; 6] = [
    aws_lc_rs::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    aws_lc_rs::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    aws_lc_rs::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    aws_lc_rs::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    aws_lc_rs::cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    aws_lc_rs::cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
];

/// The cipher suites supported by Firefox.
/// Note that some of these are not real cipher suites and their implementation doesn't match the specification.
pub static FIREFOX_TLS13_CIPHER_SUITES: [&Tls13CipherSuite; 11] = [
    aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256,
    aws_lc_rs::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
    aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384,
    aws_lc_rs::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, // fake cipher suite from the patch
    aws_lc_rs::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, // fake cipher suite from the patch
    aws_lc_rs::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, // fake cipher suite from the patch
    aws_lc_rs::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, // fake cipher suite from the patch
    aws_lc_rs::cipher_suite::TLS_RSA_WITH_AES_128_GCM_SHA256,    // fake cipher suite from the patch
    aws_lc_rs::cipher_suite::TLS_RSA_WITH_AES_256_GCM_SHA384,    // fake cipher suite from the patch
    aws_lc_rs::cipher_suite::TLS_RSA_WITH_AES_128_CBC_SHA,       // fake cipher suite from the patch
    aws_lc_rs::cipher_suite::TLS_RSA_WITH_AES_256_CBC_SHA,       // fake cipher suite from the patch
];

/// The TLS 1.2 cipher suites supported by Firefox.
pub static FIREFOX_TLS12_CIPHER_SUITES: [&Tls12CipherSuite; 6] = [
    aws_lc_rs::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    aws_lc_rs::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    aws_lc_rs::cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    aws_lc_rs::cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    aws_lc_rs::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    aws_lc_rs::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
];

/// The signature verification algorithms supported by Google Chrome.
pub static CHROME_SIGNATURE_VERIFICATION_ALGOS: WebPkiSupportedAlgorithms =
    WebPkiSupportedAlgorithms {
        all: &[
            webpki_algs_aws::ECDSA_P256_SHA256,
            webpki_algs_aws::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
            webpki_algs_aws::RSA_PKCS1_2048_8192_SHA256,
            webpki_algs_aws::ECDSA_P384_SHA384,
            webpki_algs_aws::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
            webpki_algs_aws::RSA_PKCS1_2048_8192_SHA384,
            webpki_algs_aws::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
            webpki_algs_aws::RSA_PKCS1_2048_8192_SHA512,
        ],
        mapping: &[
            (
                SignatureScheme::ECDSA_NISTP256_SHA256,
                &[webpki_algs_aws::ECDSA_P256_SHA256],
            ),
            (
                SignatureScheme::RSA_PSS_SHA256,
                &[webpki_algs_aws::RSA_PSS_2048_8192_SHA256_LEGACY_KEY],
            ),
            (
                SignatureScheme::RSA_PKCS1_SHA256,
                &[webpki_algs_aws::RSA_PKCS1_2048_8192_SHA256],
            ),
            (
                SignatureScheme::ECDSA_NISTP384_SHA384,
                &[webpki_algs_aws::ECDSA_P384_SHA384],
            ),
            (
                SignatureScheme::RSA_PSS_SHA384,
                &[webpki_algs_aws::RSA_PSS_2048_8192_SHA384_LEGACY_KEY],
            ),
            (
                SignatureScheme::RSA_PKCS1_SHA384,
                &[webpki_algs_aws::RSA_PKCS1_2048_8192_SHA384],
            ),
            (
                SignatureScheme::RSA_PSS_SHA512,
                &[webpki_algs_aws::RSA_PSS_2048_8192_SHA512_LEGACY_KEY],
            ),
            (
                SignatureScheme::RSA_PKCS1_SHA512,
                &[webpki_algs_aws::RSA_PKCS1_2048_8192_SHA512],
            ),
        ],
    };

/// The signature schemes supported by Google Chrome.
pub static CHROME_SIGNATURE_SCHEMES: &[SignatureScheme; 8] = &[
    SignatureScheme::ECDSA_NISTP256_SHA256,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PKCS1_SHA256,
    SignatureScheme::ECDSA_NISTP384_SHA384,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PKCS1_SHA512,
];

/// The signature verification algorithms supported by Firefox.
pub static FIREFOX_SIGNATURE_VERIFICATION_ALGOS: WebPkiSupportedAlgorithms =
    WebPkiSupportedAlgorithms {
        all: &[
            webpki_algs_aws::ECDSA_P256_SHA256,
            webpki_algs_aws::ECDSA_P256_SHA384,
            webpki_algs_aws::ECDSA_P384_SHA256,
            webpki_algs_aws::ECDSA_P384_SHA384,
            webpki_algs_aws::ECDSA_P384_SHA384,
            webpki_algs_aws::ECDSA_P521_SHA256,
            webpki_algs_aws::ECDSA_P521_SHA384,
            webpki_algs_aws::ECDSA_P521_SHA512,
            webpki_algs_aws::ED25519,
            webpki_algs_aws::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
            webpki_algs_aws::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
            webpki_algs_aws::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
            webpki_algs_aws::RSA_PKCS1_2048_8192_SHA256,
            webpki_algs_aws::RSA_PKCS1_2048_8192_SHA384,
            webpki_algs_aws::RSA_PKCS1_2048_8192_SHA512,
            webpki_algs_aws::RSA_PKCS1_3072_8192_SHA384,
        ],
        mapping: &[
            (
                SignatureScheme::ECDSA_NISTP256_SHA256,
                &[
                    webpki_algs_aws::ECDSA_P256_SHA256,
                    webpki_algs_aws::ECDSA_P384_SHA256,
                    webpki_algs_aws::ECDSA_P521_SHA256,
                ],
            ),
            (
                SignatureScheme::ECDSA_NISTP384_SHA384,
                &[
                    webpki_algs_aws::ECDSA_P384_SHA384,
                    webpki_algs_aws::ECDSA_P256_SHA384,
                    webpki_algs_aws::ECDSA_P521_SHA384,
                ],
            ),
            (
                SignatureScheme::ECDSA_NISTP521_SHA512,
                &[webpki_algs_aws::ECDSA_P521_SHA512],
            ),
            (
                SignatureScheme::RSA_PSS_SHA256,
                &[webpki_algs_aws::RSA_PSS_2048_8192_SHA256_LEGACY_KEY],
            ),
            (
                SignatureScheme::RSA_PSS_SHA384,
                &[webpki_algs_aws::RSA_PSS_2048_8192_SHA384_LEGACY_KEY],
            ),
            (
                SignatureScheme::RSA_PSS_SHA512,
                &[webpki_algs_aws::RSA_PSS_2048_8192_SHA512_LEGACY_KEY],
            ),
            (
                SignatureScheme::RSA_PKCS1_SHA256,
                &[webpki_algs_aws::RSA_PKCS1_2048_8192_SHA256],
            ),
            (
                SignatureScheme::RSA_PKCS1_SHA384,
                &[webpki_algs_aws::RSA_PKCS1_2048_8192_SHA384],
            ),
            (
                SignatureScheme::RSA_PKCS1_SHA512,
                &[webpki_algs_aws::RSA_PKCS1_2048_8192_SHA512],
            ),
            (
                SignatureScheme::ECDSA_SHA1_Legacy,
                &[webpki_algs_aws::ECDSA_P256_SHA256], // fake signature scheme from the patch
            ),
            (
                SignatureScheme::RSA_PKCS1_SHA1,
                &[webpki_algs_aws::RSA_PKCS1_2048_8192_SHA256], // fake signature scheme from the patch
            ),
        ],
    };

/// The signature schemes supported by Firefox.
pub static FIREFOX_SIGNATURE_SCHEMES: &[SignatureScheme; 11] = &[
    SignatureScheme::ECDSA_NISTP256_SHA256,
    SignatureScheme::ECDSA_NISTP384_SHA384,
    SignatureScheme::ECDSA_NISTP521_SHA512,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PKCS1_SHA256,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA512,
    SignatureScheme::ECDSA_SHA1_Legacy,
    SignatureScheme::RSA_PKCS1_SHA1,
];
