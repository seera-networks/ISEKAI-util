use anyhow::{Context, bail};
use axum::{Router, extract::Path, extract::State, http::StatusCode, response::IntoResponse};
use hickory_net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::{
    Resolver,
    config::{NameServerConfig, ResolverConfig, ResolverOpts},
};
use instant_acme::{
    Account, AuthorizationStatus, ChallengeType, CryptoProvider, Csr, DefaultClient, Identifier,
    NewAccount, NewOrder, Order, OrderStatus, RetryPolicy,
};
use openssl::{pkcs12::Pkcs12, pkey::PKey, x509::X509};
use reqwest::Client;
use serde::Deserialize;
use serde_json::json;
use std::{
    collections::HashMap,
    net::IpAddr,
    path::Path as FsPath,
    sync::{Arc, RwLock},
    time::Duration,
};
use tokio_util::sync::CancellationToken;
use x509_parser::{
    certification_request::X509CertificationRequest,
    extensions::{GeneralName, ParsedExtension},
    prelude::FromDer,
};

const DNS_PROPAGATION_RETRY_COUNT: usize = 30;
const DNS_PROPAGATION_RETRY_INTERVAL: Duration = Duration::from_secs(6);

/// Challenge method used for ACME domain validation.
#[derive(Clone, Debug)]
pub enum AcmeChallengeType {
    /// DNS-01 challenge via the Cloudflare API.
    Dns01 {
        cloudflare_api_token: String,
        cloudflare_zone_id: String,
    },
    /// HTTP-01 challenge served by a temporary HTTP server.
    Http01 {
        /// Address and port on which to listen for the ACME HTTP-01 verification
        /// requests (e.g. `"0.0.0.0:80"`).
        bind_addr: String,
    },
}

#[derive(Clone, Debug)]
pub struct AcmeConfig {
    pub hosts: Vec<String>,
    pub challenge: AcmeChallengeType,
    pub account_credential_path: Option<String>,
    pub directory_url: String,
    pub profile: Option<String>,
    pub cert_path: String,
    pub key_path: String,
    pub pkcs12_path: String,
}

/// A PKCS#10 certificate signing request supplied by the caller.
///
/// The private key behind the CSR never reaches this crate: it can stay in an
/// HSM, a KMS, or a file this process cannot read. Only the CSR travels.
#[derive(Clone, Debug)]
pub enum CsrSource {
    /// PEM-encoded (`-----BEGIN CERTIFICATE REQUEST-----`) bytes.
    ///
    /// Only the first `CERTIFICATE REQUEST` section is used.
    Pem(Vec<u8>),
    /// DER-encoded bytes.
    Der(Vec<u8>),
    /// Path to a file holding a PEM-encoded CSR.
    PemFile(String),
}

impl CsrSource {
    /// Decode into the `instant-acme` representation.
    fn load(&self) -> anyhow::Result<Csr<'static>> {
        Ok(match self {
            Self::Pem(pem) => Csr::from_pem(pem).context("failed to decode the PEM-encoded CSR")?,
            Self::Der(der) => Csr::from_der(der.clone()),
            Self::PemFile(path) => Csr::from_pem_file(path)
                .with_context(|| format!("failed to read the PEM-encoded CSR at {path}"))?,
        })
    }
}

/// Configuration for issuing a certificate against a caller-supplied CSR.
///
/// Unlike [`AcmeConfig`], nothing here names a key path: the ACME client never
/// sees the certificate's private key, so it can write neither a key PEM nor a
/// PKCS#12 bundle. The issued chain is returned to the caller (and optionally
/// written to `cert_path`).
#[derive(Clone, Debug)]
pub struct AcmeCsrConfig {
    /// The CSR to be signed.
    pub csr: CsrSource,
    /// The identifiers to place in the order.
    ///
    /// When empty, they are derived from the CSR's subjectAltName extension,
    /// which is the usual case: the ACME server requires the order and the CSR
    /// to name the same identifiers, so restating them here only adds a way for
    /// the two to disagree. A mismatch is caught locally, before the order is
    /// spent, by [`instant_acme::Order::validate_csr()`].
    ///
    /// This is **not** an allow-list and cannot be used as one: naming a subset
    /// of the CSR's identifiers does not narrow what is issued, it gets the CSR
    /// rejected for asking for a name the order does not authorize. See
    /// [`issue_certificate_with_csr()`] on vetting a CSR that came from
    /// somewhere else.
    ///
    /// An entry that parses as an IP address becomes an IP identifier; anything
    /// else becomes a DNS identifier, lowercased. Duplicates are dropped.
    pub hosts: Vec<String>,
    pub challenge: AcmeChallengeType,
    pub account_credential_path: Option<String>,
    pub directory_url: String,
    pub profile: Option<String>,
    /// Where to write the issued certificate chain, if anywhere.
    ///
    /// The chain is public material, so it is written with the process umask
    /// rather than through [`crate::secure_fs`].
    pub cert_path: Option<String>,
}

#[derive(Deserialize)]
struct CloudflareCreateRecordResponse {
    success: bool,
    result: Option<CloudflareRecordResult>,
}

#[derive(Deserialize)]
struct CloudflareRecordResult {
    id: String,
}

/// Shared map from ACME HTTP-01 challenge token to its key-authorization value.
type ChallengeTokenMap = Arc<RwLock<HashMap<String, String>>>;

/// Axum handler that serves the HTTP-01 ACME challenge response at
/// `/.well-known/acme-challenge/:token`.
async fn http01_challenge_handler(
    State(map): State<ChallengeTokenMap>,
    Path(token): Path<String>,
) -> impl IntoResponse {
    let map = map.read().expect("challenge token map lock poisoned");
    match map.get(&token) {
        Some(content) => (StatusCode::OK, content.clone()),
        None => (StatusCode::NOT_FOUND, String::new()),
    }
}

/// Start a temporary HTTP server for ACME HTTP-01 challenges.
///
/// Returns the join-handle of the spawned server task and a cancellation
/// token that can be used to stop it.
async fn start_http01_server(
    bind_addr: &str,
    challenge_map: ChallengeTokenMap,
) -> anyhow::Result<(tokio::task::JoinHandle<()>, CancellationToken)> {
    let listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .with_context(|| format!("failed to bind HTTP-01 challenge server to {bind_addr}"))?;
    tracing::info!("ACME HTTP-01 challenge server listening on {bind_addr}");

    let router = Router::new()
        .route(
            "/.well-known/acme-challenge/{token}",
            axum::routing::get(http01_challenge_handler),
        )
        .with_state(challenge_map);

    let stop = CancellationToken::new();
    let stop_clone = stop.clone();
    let handle = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(async move { stop_clone.cancelled().await })
            .await
            .ok();
    });

    Ok((handle, stop))
}

pub async fn ensure_certificate(config: AcmeConfig) -> anyhow::Result<()> {
    if config.hosts.is_empty() {
        return Ok(());
    }
    check_challenge_config(&config.challenge)?;

    let account = build_account(
        &config.directory_url,
        config.account_credential_path.as_deref(),
    )
    .await?;

    let identifiers = config
        .hosts
        .iter()
        .map(|host| Identifier::Dns(host.clone()))
        .collect::<Vec<_>>();
    let mut order = new_order(&account, &identifiers, config.profile.as_deref()).await?;
    if order.state().status == OrderStatus::Pending {
        solve_challenges(&mut order, &config.challenge).await?;
    }

    let private_key_pem = order.finalize().await?;
    let cert_chain_pem = order.poll_certificate(&RetryPolicy::default()).await?;

    let openssl_cert = X509::from_pem(cert_chain_pem.as_bytes())?;
    let openssl_pkey = PKey::private_key_from_pem(private_key_pem.as_bytes())?;
    let pfx = Pkcs12::builder()
        .pkey(&openssl_pkey)
        .cert(&openssl_cert)
        .build2("")?;
    let pfx_der = pfx.to_der()?;

    if let Some(parent) = FsPath::new(&config.key_path).parent()
        && !parent.as_os_str().is_empty()
        && !parent.exists()
    {
        crate::secure_fs::create_secret_dir(parent)
            .with_context(|| format!("failed to create key directory {}", parent.display()))?;
    }
    if let Some(parent) = FsPath::new(&config.pkcs12_path).parent()
        && !parent.as_os_str().is_empty()
        && !parent.exists()
    {
        crate::secure_fs::create_secret_dir(parent)
            .with_context(|| format!("failed to create PKCS#12 directory {}", parent.display()))?;
    }

    // The private key and the PKCS#12 bundle (which embeds the key) must be
    // owner-readable only; the certificate chain is public material.
    crate::secure_fs::write_secret(&config.key_path, private_key_pem)
        .with_context(|| format!("failed to write key PEM {}", config.key_path))?;
    write_cert_chain(&config.cert_path, &cert_chain_pem)?;
    crate::secure_fs::write_secret(&config.pkcs12_path, pfx_der)
        .with_context(|| format!("failed to write PKCS#12 {}", config.pkcs12_path))?;
    tracing::info!("ACME certificate written to {}", config.cert_path);
    Ok(())
}

/// Issue a certificate for a CSR the caller supplies, without ever holding the
/// certificate's private key.
///
/// The order is created for [`AcmeCsrConfig::hosts`] (by default the CSR's own
/// subjectAltName values), validated against the CSR locally before any
/// challenge is published, and finalized with the CSR as-is. Returns the issued
/// certificate chain as PEM.
///
/// Use [`ensure_certificate()`] instead when this process should generate the
/// key pair itself.
///
/// # Vetting the names
///
/// The CSR decides what the certificate is for. With `hosts` empty the order is
/// built from the CSR's own subjectAltName values, so
/// [`instant_acme::Order::validate_csr()`] compares the CSR against an order
/// derived from that same CSR and can never disagree with it. Whoever hands
/// over the CSR is therefore asking for any name these ACME credentials can
/// pass validation for — over DNS-01 with a zone-wide Cloudflare token, that is
/// every name in the zone.
///
/// Check the CSR's names against what the requester is entitled to before
/// calling this. [`AcmeCsrConfig::hosts`] cannot do it for you.
pub async fn issue_certificate_with_csr(config: AcmeCsrConfig) -> anyhow::Result<String> {
    // Before an order exists to be spent on it: a challenge that cannot work
    // fails the same way on every retry, taking an order with it each time.
    check_challenge_config(&config.challenge)?;

    let csr = config.csr.load()?;
    let identifiers = match config.hosts.is_empty() {
        true => identifiers_from_csr(&csr)?,
        false => identifiers_from_hosts(&config.hosts),
    };

    let account = build_account(
        &config.directory_url,
        config.account_credential_path.as_deref(),
    )
    .await?;
    let mut order = new_order(&account, &identifiers, config.profile.as_deref()).await?;

    // Before any challenge is solved: a CSR that does not match the order is
    // rejected at finalization, once the order has already been spent (and, for
    // DNS-01, once a TXT record has been published and waited on).
    order
        .validate_csr(&csr)
        .await
        .context("failed to check the supplied CSR against the ACME order")?;

    if order.state().status == OrderStatus::Pending {
        solve_challenges(&mut order, &config.challenge).await?;
    }

    order.finalize_with(&csr).await?;
    let cert_chain_pem = order.poll_certificate(&RetryPolicy::default()).await?;

    if let Some(cert_path) = &config.cert_path {
        write_cert_chain(cert_path, &cert_chain_pem)?;
        tracing::info!("ACME certificate written to {cert_path}");
    }
    Ok(cert_chain_pem)
}

/// The identifiers a CSR asks for, taken from its subjectAltName extension.
///
/// Duplicates are dropped, keeping the first occurrence; see [`push_unique()`].
fn identifiers_from_csr(csr: &Csr<'_>) -> anyhow::Result<Vec<Identifier>> {
    let (rest, request) = X509CertificationRequest::from_der(csr.der())
        .map_err(|err| anyhow::anyhow!("failed to parse the CSR: {err}"))?;
    if !rest.is_empty() {
        bail!("trailing data after the CSR");
    }

    let mut identifiers = Vec::new();
    for extension in request.requested_extensions().into_iter().flatten() {
        let ParsedExtension::SubjectAlternativeName(san) = extension else {
            continue;
        };

        for name in &san.general_names {
            let identifier = match name {
                GeneralName::DNSName(name) => Identifier::Dns(name.to_ascii_lowercase()),
                GeneralName::IPAddress(bytes) => match <[u8; 4]>::try_from(*bytes) {
                    Ok(octets) => Identifier::Ip(IpAddr::from(octets)),
                    Err(_) => match <[u8; 16]>::try_from(*bytes) {
                        Ok(octets) => Identifier::Ip(IpAddr::from(octets)),
                        Err(_) => bail!("invalid IP address in the CSR's subjectAltName"),
                    },
                },
                // Only DNS names and IP addresses map onto ACME identifiers.
                // Anything else the CA would refuse to issue for anyway, and
                // `Order::validate_csr()` reports it against the order.
                _ => continue,
            };
            push_unique(&mut identifiers, identifier);
        }
    }

    if identifiers.is_empty() {
        bail!(
            "the CSR has no DNS name or IP address in its subjectAltName extension, \
             so there is nothing to order a certificate for"
        );
    }
    Ok(identifiers)
}

/// The identifiers for the configured hosts, deduplicated.
fn identifiers_from_hosts(hosts: &[String]) -> Vec<Identifier> {
    let mut identifiers = Vec::with_capacity(hosts.len());
    for host in hosts {
        push_unique(&mut identifiers, identifier(host));
    }
    identifiers
}

/// The ACME identifier for a host: an IP address literal becomes an IP
/// identifier, anything else a DNS identifier.
fn identifier(host: &str) -> Identifier {
    match host.parse::<IpAddr>() {
        Ok(addr) => Identifier::Ip(addr),
        // DNS names are matched case-insensitively by the CA, so fold the case
        // here — otherwise `push_unique()` sees two spellings as two names.
        Err(_) => Identifier::Dns(host.to_ascii_lowercase()),
    }
}

/// Append `identifier` unless the list already has it.
///
/// An ACME server rejects an order that names the same identifier twice, and
/// two spellings of one name are one identifier to it: `Example.COM` and
/// `example.com`, or `2001:db8::1` and `2001:0db8:0000::0001`. Both are already
/// normalized by the time they get here — DNS names lowercased, IP addresses
/// parsed into an [`IpAddr`] — so plain equality is enough.
fn push_unique(identifiers: &mut Vec<Identifier>, identifier: Identifier) {
    if !identifiers.contains(&identifier) {
        identifiers.push(identifier);
    }
}

/// Write a certificate chain, creating its parent directory if needed.
fn write_cert_chain(cert_path: &str, cert_chain_pem: &str) -> anyhow::Result<()> {
    if let Some(parent) = FsPath::new(cert_path).parent()
        && !parent.as_os_str().is_empty()
        && !parent.exists()
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create cert directory {}", parent.display()))?;
    }
    std::fs::write(cert_path, cert_chain_pem)
        .with_context(|| format!("failed to write cert PEM {cert_path}"))
}

/// Load the ACME account from `credential_path`, creating (and saving) one when
/// the file does not exist yet. Without a path, a throwaway account is created.
async fn build_account(
    directory_url: &str,
    credential_path: Option<&str>,
) -> anyhow::Result<Account> {
    let build_account_builder = || -> anyhow::Result<_> {
        let provider = CryptoProvider::aws_lc_rs();
        let rustls_crypto_provider = rustls::crypto::aws_lc_rs::default_provider();
        Ok(Account::builder(
            Box::new(DefaultClient::new(Arc::new(rustls_crypto_provider))?),
            provider,
        )?)
    };

    let account = if let Some(credential_path) = credential_path {
        if FsPath::new(credential_path).exists() {
            let credentials = std::fs::read_to_string(credential_path)
                .with_context(|| format!("failed to read ACME credentials at {credential_path}"))?;
            build_account_builder()?
                .from_credentials(serde_json::from_str(&credentials)?)
                .await?
        } else {
            let (account, credentials) = build_account_builder()?
                .create(
                    &NewAccount {
                        contact: &[],
                        terms_of_service_agreed: true,
                        only_return_existing: false,
                    },
                    directory_url.to_owned(),
                    None,
                )
                .await?;
            if let Some(parent) = FsPath::new(credential_path).parent()
                && !parent.as_os_str().is_empty()
                && !parent.exists()
            {
                crate::secure_fs::create_secret_dir(parent).with_context(|| {
                    format!(
                        "failed to create ACME credential directory {}",
                        parent.display()
                    )
                })?;
            }
            // Account credentials contain the ACME account private key; they
            // must not be world-readable.
            crate::secure_fs::write_secret(credential_path, serde_json::to_string(&credentials)?)
                .with_context(|| format!("failed to write ACME credentials at {credential_path}"))?;
            account
        }
    } else {
        let (account, _credentials) = build_account_builder()?
            .create(
                &NewAccount {
                    contact: &[],
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                directory_url.to_owned(),
                None,
            )
            .await?;
        account
    };

    Ok(account)
}

/// Create an order for `identifiers`, under `profile` if the CA offers one.
async fn new_order(
    account: &Account,
    identifiers: &[Identifier],
    profile: Option<&str>,
) -> anyhow::Result<Order> {
    let new_order = NewOrder::new(identifiers);
    let new_order = match profile {
        Some(profile) => new_order.profile(profile),
        None => new_order,
    };
    Ok(account.new_order(&new_order).await?)
}

/// Answer every pending authorization on `order` with the configured challenge
/// type, leaving the order ready to be finalized.
async fn solve_challenges(order: &mut Order, challenge: &AcmeChallengeType) -> anyhow::Result<()> {
    check_challenge_config(challenge)?;
    match challenge {
        AcmeChallengeType::Dns01 {
            cloudflare_api_token,
            cloudflare_zone_id,
        } => ensure_certificate_dns01(order, cloudflare_api_token, cloudflare_zone_id).await,
        AcmeChallengeType::Http01 { bind_addr } => {
            ensure_certificate_http01(order, bind_addr).await
        }
    }
}

/// Reject a challenge configuration that cannot work.
///
/// Worth doing before an order is created: the order is spent either way, and
/// a missing credential fails identically on every retry.
fn check_challenge_config(challenge: &AcmeChallengeType) -> anyhow::Result<()> {
    match challenge {
        AcmeChallengeType::Dns01 {
            cloudflare_api_token,
            cloudflare_zone_id,
        } if cloudflare_api_token.is_empty() || cloudflare_zone_id.is_empty() => {
            bail!("ACME DNS-01 challenge selected but Cloudflare token/zone id is not configured")
        }
        _ => Ok(()),
    }
}

/// Handle ACME DNS-01 challenges for all pending authorizations using the
/// Cloudflare API.
async fn ensure_certificate_dns01(
    order: &mut instant_acme::Order,
    cloudflare_api_token: &str,
    cloudflare_zone_id: &str,
) -> anyhow::Result<()> {
    let client = Client::new();
    let mut record_ids = Vec::new();

    let outcome = dns01_challenges(
        order,
        &client,
        cloudflare_api_token,
        cloudflare_zone_id,
        &mut record_ids,
    )
    .await;

    // Only now, once the order has stopped being pending. `set_ready` merely
    // asks the ACME server to validate; it queries `_acme-challenge` afterwards,
    // on its own schedule. Deleting the record before that query lands makes the
    // authorization — and so the order — Invalid, intermittently and for no
    // visible reason.
    for record_id in &record_ids {
        if let Err(err) = client
            .delete(format!(
                "https://api.cloudflare.com/client/v4/zones/{cloudflare_zone_id}/dns_records/{record_id}"
            ))
            .bearer_auth(cloudflare_api_token)
            .send()
            .await
        {
            tracing::warn!("failed to delete Cloudflare TXT challenge record {record_id}: {err}");
        }
    }

    outcome
}

/// Publish and validate the DNS-01 challenges, collecting the created record ids
/// into `record_ids` for the caller to clean up.
async fn dns01_challenges(
    order: &mut instant_acme::Order,
    client: &Client,
    cloudflare_api_token: &str,
    cloudflare_zone_id: &str,
    record_ids: &mut Vec<String>,
) -> anyhow::Result<()> {
    let mut authorizations = order.authorizations();

    while let Some(result) = authorizations.next().await {
        let mut authorization = result?;
        match authorization.status {
            AuthorizationStatus::Pending => {}
            AuthorizationStatus::Valid => continue,
            status => bail!("unsupported authorization status: {status:?}"),
        }

        let mut challenge = authorization
            .challenge(ChallengeType::Dns01)
            .ok_or_else(|| anyhow::anyhow!("dns-01 challenge not found"))?;
        let dns_identifier = match challenge.identifier().identifier {
            Identifier::Dns(dns) => dns.to_string(),
            _ => bail!("unsupported non-DNS identifier type for dns-01 challenge"),
        };
        let ips = crate::dns::get_name_servers(&dns_identifier)
            .await
            .with_context(|| format!("failed to get NS servers for {}", challenge.identifier()))?;

        let mut ns_configs = Vec::new();
        for ip in ips {
            tracing::debug!("querying ACME challenge propagation via NS server {ip}");
            let ns_config = NameServerConfig::udp_and_tcp(ip);
            ns_configs.push(ns_config);
        }
        let resolver_config = ResolverConfig::from_parts(None, vec![], ns_configs);
        let mut resolver_opts = ResolverOpts::default();
        resolver_opts.negative_max_ttl = Some(std::time::Duration::from_secs(0));
        let resolver = Resolver::builder_with_config(resolver_config, TokioRuntimeProvider::new())
            .with_options(resolver_opts)
            .build()?;

        let dns_name = format!("_acme-challenge.{dns_identifier}");
        let key_authorization = challenge.key_authorization()?;
        let dns_value = key_authorization.dns_value().to_string();
        let create_resp = client
            .post(format!(
                "https://api.cloudflare.com/client/v4/zones/{cloudflare_zone_id}/dns_records"
            ))
            .bearer_auth(cloudflare_api_token)
            .json(&json!({
                "type": "TXT",
                "name": dns_name,
                "content": format!("\"{}\"", dns_value),
                "ttl": 120,
                "proxied": false
            }))
            .send()
            .await?
            .error_for_status()?
            .json::<CloudflareCreateRecordResponse>()
            .await?;
        if !create_resp.success {
            bail!("failed to create Cloudflare TXT record");
        }
        tracing::debug!(
            "created Cloudflare TXT record for {} with value {}",
            dns_name,
            dns_value
        );

        if let Some(record) = create_resp.result {
            record_ids.push(record.id);
        }
        let expected_dns_value = dns_value.clone();
        let mut propagated = false;
        for _ in 0..DNS_PROPAGATION_RETRY_COUNT {
            let lookup = resolver
                .lookup(format!("{dns_name}."), RecordType::TXT)
                .await;
            if let Ok(lookup) = lookup
                && lookup
                    .answers()
                    .iter()
                    .any(|txt| txt.to_string().contains(&expected_dns_value))
            {
                tracing::debug!(
                    "DNS-01 challenge for {} successfully propagated with value {}",
                    challenge.identifier(),
                    dns_value
                );
                propagated = true;
                break;
            }
            tracing::debug!(
                "DNS-01 challenge for {} not propagated yet, retrying...",
                challenge.identifier()
            );
            tokio::time::sleep(DNS_PROPAGATION_RETRY_INTERVAL).await;
        }
        if !propagated {
            bail!(
                "dns challenge did not propagate in time for {}",
                challenge.identifier()
            );
        }

        challenge.set_ready().await?;
    }

    let status = order.poll_ready(&RetryPolicy::default()).await?;
    if status != OrderStatus::Ready {
        bail!("unexpected order status after dns-01 challenges: {status:?}");
    }
    Ok(())
}

/// Handle ACME HTTP-01 challenges for all pending authorizations by running a
/// temporary HTTP server that answers `/.well-known/acme-challenge/:token`
/// requests.
async fn ensure_certificate_http01(
    order: &mut instant_acme::Order,
    bind_addr: &str,
) -> anyhow::Result<()> {
    let challenge_map: ChallengeTokenMap = Arc::new(RwLock::new(HashMap::new()));
    let (server_handle, stop_token) =
        start_http01_server(bind_addr, Arc::clone(&challenge_map)).await?;

    let result = async {
        let mut authorizations = order.authorizations();

        while let Some(result) = authorizations.next().await {
            let mut authorization = result?;
            match authorization.status {
                AuthorizationStatus::Pending => {}
                AuthorizationStatus::Valid => continue,
                status => bail!("unsupported authorization status: {status:?}"),
            }

            let mut challenge = authorization
                .challenge(ChallengeType::Http01)
                .ok_or_else(|| anyhow::anyhow!("http-01 challenge not found"))?;

            let key_authorization = challenge.key_authorization()?;
            let token = challenge.token.clone();
            let content = key_authorization.as_str().to_string();
            tracing::debug!(
                "registering HTTP-01 challenge token={token} for {}",
                challenge.identifier()
            );
            {
                let mut map = challenge_map
                    .write()
                    .expect("challenge token map lock poisoned");
                map.insert(token, content);
            }

            challenge.set_ready().await?;
        }

        let status = order.poll_ready(&RetryPolicy::default()).await?;
        if status != OrderStatus::Ready {
            bail!("unexpected order status after http-01 challenges: {status:?}");
        }
        Ok(())
    }
    .await;

    // Stop the temporary HTTP server regardless of outcome.
    stop_token.cancel();
    server_handle.await.ok();

    result
}

/// Returns the time remaining until the leaf certificate at `cert_path` expires.
///
/// Returns [`Duration::ZERO`] when the certificate has already expired.
/// Returns an error when the file cannot be read or does not contain a valid PEM
/// certificate.
pub fn check_cert_expiry(cert_path: &str) -> anyhow::Result<Duration> {
    let pem_data = std::fs::read(cert_path)
        .with_context(|| format!("failed to read certificate at {cert_path}"))?;

    let (_, pem) = x509_parser::pem::parse_x509_pem(&pem_data)
        .map_err(|e| anyhow::anyhow!("failed to parse PEM at {cert_path}: {e:?}"))?;
    let cert = pem
        .parse_x509()
        .map_err(|e| anyhow::anyhow!("failed to parse X.509 certificate: {e:?}"))?;

    let not_after_ts = cert.validity().not_after.timestamp();
    let now_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_secs() as i64;

    if not_after_ts <= now_ts {
        return Ok(Duration::ZERO);
    }
    Ok(Duration::from_secs((not_after_ts - now_ts) as u64))
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::{
        ec::{EcGroup, EcKey},
        hash::MessageDigest,
        nid::Nid,
        pkey::Private,
        stack::Stack,
        x509::{X509ReqBuilder, extension::SubjectAlternativeName},
    };

    fn signing_key() -> PKey<Private> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap()
    }

    /// A CSR asking for `dns` and `ips`, signed by a throwaway key. No
    /// subjectAltName extension is added when both are empty.
    fn csr_der(dns: &[&str], ips: &[&str]) -> Vec<u8> {
        let key = signing_key();
        let mut builder = X509ReqBuilder::new().unwrap();
        builder.set_pubkey(&key).unwrap();

        if !dns.is_empty() || !ips.is_empty() {
            let mut san = SubjectAlternativeName::new();
            for name in dns {
                san.dns(name);
            }
            for ip in ips {
                san.ip(ip);
            }
            let extension = san.build(&builder.x509v3_context(None)).unwrap();
            let mut extensions = Stack::new().unwrap();
            extensions.push(extension).unwrap();
            builder.add_extensions(&extensions).unwrap();
        }

        builder.sign(&key, MessageDigest::sha256()).unwrap();
        builder.build().to_der().unwrap()
    }

    fn identifiers(dns: &[&str], ips: &[&str]) -> anyhow::Result<Vec<Identifier>> {
        identifiers_from_csr(&Csr::from_der(csr_der(dns, ips)))
    }

    #[test]
    fn csr_identifiers_cover_dns_and_ip() {
        let found = identifiers(
            &["example.com", "www.example.com"],
            &["192.0.2.1", "2001:db8::1"],
        )
        .unwrap();
        assert_eq!(
            found,
            vec![
                Identifier::Dns("example.com".to_owned()),
                Identifier::Dns("www.example.com".to_owned()),
                Identifier::Ip("192.0.2.1".parse().unwrap()),
                Identifier::Ip("2001:db8::1".parse().unwrap()),
            ]
        );
    }

    #[test]
    fn csr_identifiers_keep_the_wildcard() {
        // An ACME order asks for a wildcard by naming `*.example.com`; the
        // authorization comes back as `example.com` with the wildcard bit set.
        assert_eq!(
            identifiers(&["*.example.com"], &[]).unwrap(),
            vec![Identifier::Dns("*.example.com".to_owned())]
        );
    }

    #[test]
    fn csr_identifiers_are_deduplicated() {
        // Repeating an identifier in an order gets it rejected by the server,
        // and a DNS name repeated in another case is the same identifier.
        assert_eq!(
            identifiers(
                &["example.com", "example.com", "Example.COM"],
                &[
                    "192.0.2.1",
                    "192.0.2.1",
                    "2001:db8::1",
                    "2001:0db8:0000::0001"
                ],
            )
            .unwrap(),
            vec![
                Identifier::Dns("example.com".to_owned()),
                Identifier::Ip("192.0.2.1".parse().unwrap()),
                Identifier::Ip("2001:db8::1".parse().unwrap()),
            ]
        );
    }

    #[test]
    fn host_identifiers_are_normalized_and_deduplicated() {
        let hosts = [
            "Example.COM",
            "example.com",
            "2001:db8::1",
            "2001:0db8:0000::0001",
        ]
        .map(str::to_owned);
        assert_eq!(
            identifiers_from_hosts(&hosts),
            vec![
                Identifier::Dns("example.com".to_owned()),
                Identifier::Ip("2001:db8::1".parse().unwrap()),
            ]
        );
    }

    #[test]
    fn dns01_without_cloudflare_credentials_is_rejected() {
        let missing = AcmeChallengeType::Dns01 {
            cloudflare_api_token: String::new(),
            cloudflare_zone_id: "zone".to_owned(),
        };
        let err = check_challenge_config(&missing).unwrap_err().to_string();
        assert!(err.contains("Cloudflare token/zone id"), "{err}");

        let configured = AcmeChallengeType::Dns01 {
            cloudflare_api_token: "token".to_owned(),
            cloudflare_zone_id: "zone".to_owned(),
        };
        assert!(check_challenge_config(&configured).is_ok());
        assert!(
            check_challenge_config(&AcmeChallengeType::Http01 {
                bind_addr: "0.0.0.0:80".to_owned(),
            })
            .is_ok()
        );
    }

    #[test]
    fn csr_without_subject_alt_name_is_rejected() {
        let err = identifiers(&[], &[]).unwrap_err().to_string();
        assert!(err.contains("nothing to order a certificate for"), "{err}");
    }

    #[test]
    fn trailing_data_after_the_csr_is_rejected() {
        let mut der = csr_der(&["example.com"], &[]);
        der.push(0);
        let err = identifiers_from_csr(&Csr::from_der(der))
            .unwrap_err()
            .to_string();
        assert!(err.contains("trailing data"), "{err}");
    }

    #[test]
    fn csr_sources_decode_to_the_same_der() {
        let der = csr_der(&["example.com"], &[]);
        let pem = openssl::x509::X509Req::from_der(&der)
            .unwrap()
            .to_pem()
            .unwrap();

        let dir = std::env::temp_dir().join(format!("isekai-util-csr-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.csr");
        std::fs::write(&path, &pem).unwrap();

        for source in [
            CsrSource::Der(der.clone()),
            CsrSource::Pem(pem.clone()),
            CsrSource::PemFile(path.to_str().unwrap().to_owned()),
        ] {
            assert_eq!(source.load().unwrap().der(), der.as_slice(), "{source:?}");
        }

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn hosts_map_to_dns_or_ip_identifiers() {
        assert_eq!(
            identifier("example.com"),
            Identifier::Dns("example.com".to_owned())
        );
        assert_eq!(
            identifier("192.0.2.1"),
            Identifier::Ip("192.0.2.1".parse().unwrap())
        );
        assert_eq!(
            identifier("2001:db8::1"),
            Identifier::Ip("2001:db8::1".parse().unwrap())
        );
    }
}
