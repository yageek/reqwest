#[cfg(feature = "rustls-tls")]
use rustls::{RootCertStore, ServerCertVerified, ServerCertVerifier, TLSError};

#[cfg(feature = "rustls-tls")]
use tokio_rustls::webpki::DNSNameRef;
use webpki::DNSName;

use crate::Certificate;
struct PinningDomainConfiguration<'a> {
    host: &'a str,
    hashes: &'a [&'a str],
}

impl<'a> PinningDomainConfiguration<'a> {
    fn new(host: &'a str, hashes: &'a [&'a str]) -> Self {
        PinningDomainConfiguration { host, hashes }
    }
}

#[cfg(feature = "rustls-tls")]
struct PinningVerifier<'a> {
    configurations: Vec<PinningDomainConfiguration<'a>>,
}

impl<'a> PinningVerifier<'a> {
    fn has_policy<'b>(&self, domain: &'b str) -> bool {
        self.configurations
            .iter()
            .filter(|p| p.host == domain)
            .next()
            .is_some()
    }
}

#[cfg(feature = "rustls")]
impl<'a> ServerCertVerifier for PinningVerifier<'a> {
    fn verify_server_cert(
        &self,
        roots: &RootCertStore,
        presented_certs: &[rustls::Certificate],
        dns_name: DNSNameRef<'_>,
        ocsp_response: &[u8],
    ) -> Result<ServerCertVerified, TLSError> {
        let name = &dns_name.to_owned();

        let val = <DNSName as AsRef<str>>::as_ref(&name);
        if !self.has_policy(val) {
            Ok(ServerCertVerified::assertion())
        } else {
            // TODO: Expiration policy

            // We validate all the chain

            // For eveery certificate check something
            let leaf_cert_valid: Vec<webpki::EndEntityCert> = presented_certs
                .into_iter()
                .flat_map(|c| webpki::EndEntityCert::from(&c.0).ok())
                .collect();

            Ok(ServerCertVerified::assertion())
        }
    }
}
