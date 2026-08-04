#[cfg(feature = "impit")]
use crate::KeyLogFile;
#[cfg(not(feature = "impit"))]
use crate::NoKeyLog;
use alloc::vec::Vec;
use core::marker::PhantomData;
#[cfg(feature = "impit")]
use std::vec;

use pki_types::{CertificateDer, PrivateKeyDer};

use super::client_conn::Resumption;
use crate::builder::{ConfigBuilder, WantsVerifier};
use crate::client::{ClientConfig, EchMode, ResolvesClientCert, handy};
use crate::error::Error;
use crate::sign::{CertifiedKey, SingleCertAndKey};
use crate::sync::Arc;
#[cfg(not(feature = "impit"))]
use crate::version::TLS13;
use crate::webpki::{self, WebPkiServerVerifier};
use crate::{WantsVersions, compress, verify, versions};

impl ConfigBuilder<ClientConfig, WantsVersions> {
    /// Enable Encrypted Client Hello (ECH) in the given mode.
    ///
    /// This implicitly selects TLS 1.3 as the only supported protocol version to meet the
    /// requirement to support ECH.
    ///
    /// The `ClientConfig` that will be produced by this builder will be specific to the provided
    /// [`crate::client::EchConfig`] and may not be appropriate for all connections made by the program.
    /// In this case the configuration should only be shared by connections intended for domains
    /// that offer the provided [`crate::client::EchConfig`] in their DNS zone.
    pub fn with_ech(
        self,
        mode: EchMode,
    ) -> Result<ConfigBuilder<ClientConfig, WantsVerifier>, Error> {
        #[cfg(not(feature = "impit"))]
        let mut res = self.with_protocol_versions(&[&TLS13][..])?;
        #[cfg(feature = "impit")]
        let mut res = self.with_safe_default_protocol_versions()?; // It's alright to send the ECH with TLS 1.2, worst case, the server will ignore it.

        res.state.client_ech_mode = Some(mode);
        Ok(res)
    }
}

impl ConfigBuilder<ClientConfig, WantsVerifier> {
    /// Choose how to verify server certificates.
    ///
    /// Using this function does not configure revocation.  If you wish to
    /// configure revocation, instead use:
    ///
    /// ```diff
    /// - .with_root_certificates(root_store)
    /// + .with_webpki_verifier(
    /// +   WebPkiServerVerifier::builder_with_provider(root_store, crypto_provider)
    /// +   .with_crls(...)
    /// +   .build()?
    /// + )
    /// ```
    pub fn with_root_certificates(
        self,
        root_store: impl Into<Arc<webpki::RootCertStore>>,
    ) -> ConfigBuilder<ClientConfig, WantsClientCert> {
        let algorithms = self
            .provider
            .signature_verification_algorithms;
        self.with_webpki_verifier(
            WebPkiServerVerifier::new_without_revocation(root_store, algorithms).into(),
        )
    }

    /// Choose how to verify server certificates using a webpki verifier.
    ///
    /// See [`webpki::WebPkiServerVerifier::builder`] and
    /// [`webpki::WebPkiServerVerifier::builder_with_provider`] for more information.
    pub fn with_webpki_verifier(
        self,
        verifier: Arc<WebPkiServerVerifier>,
    ) -> ConfigBuilder<ClientConfig, WantsClientCert> {
        ConfigBuilder {
            state: WantsClientCert {
                versions: self.state.versions,
                verifier,
                client_ech_mode: self.state.client_ech_mode,
            },
            provider: self.provider,
            time_provider: self.time_provider,
            side: PhantomData,
        }
    }

    /// Access configuration options whose use is dangerous and requires
    /// extra care.
    pub fn dangerous(self) -> danger::DangerousClientConfigBuilder {
        danger::DangerousClientConfigBuilder { cfg: self }
    }
}

/// Container for unsafe APIs
pub(super) mod danger {
    use core::marker::PhantomData;

    use crate::client::WantsClientCert;
    use crate::sync::Arc;
    use crate::{ClientConfig, ConfigBuilder, WantsVerifier, verify};

    /// Accessor for dangerous configuration options.
    #[derive(Debug)]
    pub struct DangerousClientConfigBuilder {
        /// The underlying ClientConfigBuilder
        pub cfg: ConfigBuilder<ClientConfig, WantsVerifier>,
    }

    impl DangerousClientConfigBuilder {
        /// Set a custom certificate verifier.
        pub fn with_custom_certificate_verifier(
            self,
            verifier: Arc<dyn verify::ServerCertVerifier>,
        ) -> ConfigBuilder<ClientConfig, WantsClientCert> {
            ConfigBuilder {
                state: WantsClientCert {
                    versions: self.cfg.state.versions,
                    verifier,
                    client_ech_mode: self.cfg.state.client_ech_mode,
                },
                provider: self.cfg.provider,
                time_provider: self.cfg.time_provider,
                side: PhantomData,
            }
        }
    }
}

#[cfg(feature = "impit")]
pub use crate::crypto::emulation::{
    FingerprintCertCompressionAlgorithm, FingerprintCipherSuite, FingerprintKeyExchangeGroup,
    FingerprintSignatureAlgorithm, TlsExtensionsConfig, TlsFingerprint,
};

/// A config builder state where the caller needs to supply whether and how to provide a client
/// certificate.
///
/// For more information, see the [`ConfigBuilder`] documentation.
#[derive(Clone)]
pub struct WantsClientCert {
    versions: versions::EnabledVersions,
    verifier: Arc<dyn verify::ServerCertVerifier>,
    client_ech_mode: Option<EchMode>,
}

impl ConfigBuilder<ClientConfig, WantsClientCert> {
    /// Enable TLS fingerprinting with a custom fingerprint.
    #[cfg(feature = "impit")]
    pub fn with_tls_fingerprint(
        self,
        fingerprint: TlsFingerprint,
    ) -> ConfigBuilder<ClientConfig, WantsClientCertWithTlsFingerprint> {
        ConfigBuilder {
            state: WantsClientCertWithTlsFingerprint {
                versions: self.state.versions,
                verifier: self.state.verifier,
                client_ech_mode: self.state.client_ech_mode,
                tls_fingerprint: fingerprint,
            },
            provider: self.provider,
            time_provider: self.time_provider,
            side: PhantomData,
        }
    }

    /// Sets a single certificate chain and matching private key for use
    /// in client authentication.
    ///
    /// `cert_chain` is a vector of DER-encoded certificates.
    /// `key_der` is a DER-encoded private key as PKCS#1, PKCS#8, or SEC1. The
    /// `aws-lc-rs` and `ring` [`CryptoProvider`][crate::CryptoProvider]s support
    /// all three encodings, but other `CryptoProviders` may not.
    ///
    /// This function fails if `key_der` is invalid.
    pub fn with_client_auth_cert(
        self,
        cert_chain: Vec<CertificateDer<'static>>,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<ClientConfig, Error> {
        let certified_key = CertifiedKey::from_der(cert_chain, key_der, &self.provider)?;
        Ok(self.with_client_cert_resolver(Arc::new(SingleCertAndKey::from(certified_key))))
    }

    /// Do not support client auth.
    pub fn with_no_client_auth(self) -> ClientConfig {
        self.with_client_cert_resolver(Arc::new(handy::FailResolveClientCert {}))
    }

    /// Sets a custom [`ResolvesClientCert`].
    pub fn with_client_cert_resolver(
        self,
        client_auth_cert_resolver: Arc<dyn ResolvesClientCert>,
    ) -> ClientConfig {
        #[cfg(feature = "tls12")]
        let require_ems = self.provider.fips();

        ClientConfig {
            provider: self.provider,
            alpn_protocols: Vec::new(),
            #[cfg(feature = "impit")]
            tls_fingerprint: None,
            check_selected_alpn: true,
            resumption: Resumption::default(),
            max_fragment_size: None,
            client_auth_cert_resolver,
            versions: self.state.versions,
            enable_sni: true,
            verifier: self.state.verifier,
            #[cfg(feature = "impit")]
            key_log: Arc::new(KeyLogFile::new()),
            #[cfg(not(feature = "impit"))]
            key_log: Arc::new(NoKeyLog {}),
            enable_secret_extraction: false,
            enable_early_data: false,
            #[cfg(feature = "tls12")]
            require_ems,
            time_provider: self.time_provider,
            cert_compressors: compress::default_cert_compressors().to_vec(),
            cert_compression_cache: Arc::new(compress::CompressionCache::default()),
            cert_decompressors: compress::default_cert_decompressors().to_vec(),
            ech_mode: self.state.client_ech_mode,
            send_ticket_request: None,
        }
    }
}

/// A config builder state where the caller needs to supply whether and how to provide a client
/// certificate, with TLS fingerprint enabled.
///
/// For more information, see the [`ConfigBuilder`] documentation.
#[cfg(feature = "impit")]
#[derive(Clone)]
pub struct WantsClientCertWithTlsFingerprint {
    versions: versions::EnabledVersions,
    verifier: Arc<dyn verify::ServerCertVerifier>,
    client_ech_mode: Option<EchMode>,
    tls_fingerprint: TlsFingerprint,
}

#[cfg(feature = "impit")]
impl ConfigBuilder<ClientConfig, WantsClientCertWithTlsFingerprint> {
    /// Sets a single certificate chain and matching private key for use
    /// in client authentication.
    ///
    /// `cert_chain` is a vector of DER-encoded certificates.
    /// `key_der` is a DER-encoded private key as PKCS#1, PKCS#8, or SEC1. The
    /// `aws-lc-rs` and `ring` [`CryptoProvider`][crate::CryptoProvider]s support
    /// all three encodings, but other `CryptoProviders` may not.
    ///
    /// This function fails if `key_der` is invalid.
    pub fn with_client_auth_cert(
        self,
        cert_chain: Vec<CertificateDer<'static>>,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<ClientConfig, Error> {
        let certified_key = CertifiedKey::from_der(cert_chain, key_der, &self.provider)?;
        Ok(self.with_client_cert_resolver(Arc::new(SingleCertAndKey::from(certified_key))))
    }

    /// Do not support client auth.
    pub fn with_no_client_auth(self) -> ClientConfig {
        self.with_client_cert_resolver(Arc::new(handy::FailResolveClientCert {}))
    }

    /// Sets a custom [`ResolvesClientCert`].
    pub fn with_client_cert_resolver(
        self,
        client_auth_cert_resolver: Arc<dyn ResolvesClientCert>,
    ) -> ClientConfig {
        use crate::crypto::emulation::FingerprintCertCompressionAlgorithm;

        // Determine cert compression based on fingerprint
        let (cert_compressors, cert_decompressors) = if let Some(ref compression) = self
            .state
            .tls_fingerprint
            .cert_compression
        {
            let compressors: Vec<_> = compression
                .iter()
                .filter_map(|alg| match alg {
                    FingerprintCertCompressionAlgorithm::Brotli => {
                        Some(compress::BROTLI_COMPRESSOR)
                    }
                    FingerprintCertCompressionAlgorithm::Zlib => Some(compress::ZLIB_COMPRESSOR),
                    _ => None, // Zstd not implemented yet
                })
                .collect();
            let decompressors: Vec<_> = compression
                .iter()
                .filter_map(|alg| match alg {
                    FingerprintCertCompressionAlgorithm::Brotli => {
                        Some(compress::BROTLI_DECOMPRESSOR)
                    }
                    FingerprintCertCompressionAlgorithm::Zlib => Some(compress::ZLIB_DECOMPRESSOR),
                    _ => None,
                })
                .collect();
            (compressors, decompressors)
        } else {
            (vec![], vec![])
        };

        ClientConfig {
            tls_fingerprint: Some(self.state.tls_fingerprint),
            provider: self.provider,
            check_selected_alpn: true,
            resumption: Resumption::default(),
            max_fragment_size: None,
            client_auth_cert_resolver,
            versions: self.state.versions,
            enable_sni: true,
            verifier: self.state.verifier,
            enable_secret_extraction: false,
            enable_early_data: false,
            #[cfg(feature = "tls12")]
            require_ems: cfg!(feature = "fips"),
            time_provider: self.time_provider,
            alpn_protocols: vec![], // Will be set by the caller or use fingerprint.alpn_protocols
            key_log: Arc::new(KeyLogFile::new()),
            cert_compressors,
            cert_decompressors,
            cert_compression_cache: Arc::new(compress::CompressionCache::default()),
            ech_mode: self.state.client_ech_mode,
            send_ticket_request: None,
        }
    }
}
