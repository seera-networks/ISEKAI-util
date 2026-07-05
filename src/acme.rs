use anyhow::{Context, bail};
use axum::{Router, extract::Path, extract::State, http::StatusCode, response::IntoResponse};
use hickory_net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::{
    Resolver,
    config::{NameServerConfig, ResolverConfig, ResolverOpts},
};
use instant_acme::{
    Account, AuthorizationStatus, ChallengeType, CryptoProvider, DefaultClient, Identifier,
    NewAccount, NewOrder, OrderStatus, RetryPolicy,
};
use openssl::{pkcs12::Pkcs12, pkey::PKey, x509::X509};
use reqwest::Client;
use serde::Deserialize;
use serde_json::json;
use std::{
    collections::HashMap,
    path::Path as FsPath,
    sync::{Arc, RwLock},
    time::Duration,
};
use tokio_util::sync::CancellationToken;

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

    let build_account_builder = || -> anyhow::Result<_> {
        let provider = CryptoProvider::aws_lc_rs();
        let rustls_crypto_provider = rustls::crypto::aws_lc_rs::default_provider();
        Ok(Account::builder(
            Box::new(DefaultClient::new(Arc::new(rustls_crypto_provider))?),
            provider,
        )?)
    };

    let account = if let Some(credential_path) = &config.account_credential_path {
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
                    config.directory_url.clone(),
                    None,
                )
                .await?;
            if let Some(parent) = FsPath::new(credential_path).parent()
                && !parent.as_os_str().is_empty()
                && !parent.exists()
            {
                std::fs::create_dir_all(parent).with_context(|| {
                    format!(
                        "failed to create ACME credential directory {}",
                        parent.display()
                    )
                })?;
            }
            std::fs::write(credential_path, serde_json::to_string(&credentials)?).with_context(
                || format!("failed to write ACME credentials at {credential_path}"),
            )?;
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
                config.directory_url.clone(),
                None,
            )
            .await?;
        account
    };

    let identifiers = config
        .hosts
        .iter()
        .map(|host| Identifier::Dns(host.clone()))
        .collect::<Vec<_>>();
    let new_order = NewOrder::new(&identifiers);
    let new_order = if let Some(profile) = &config.profile {
        new_order.profile(profile)
    } else {
        new_order
    };
    let mut order = account.new_order(&new_order).await?;
    if order.state().status == OrderStatus::Pending {
        match &config.challenge {
            AcmeChallengeType::Dns01 {
                cloudflare_api_token,
                cloudflare_zone_id,
            } => {
                if cloudflare_api_token.is_empty() || cloudflare_zone_id.is_empty() {
                    bail!(
                        "ACME DNS-01 challenge selected but Cloudflare token/zone id is not configured"
                    );
                }
                ensure_certificate_dns01(&mut order, cloudflare_api_token, cloudflare_zone_id)
                    .await?;
            }
            AcmeChallengeType::Http01 { bind_addr } => {
                ensure_certificate_http01(&mut order, bind_addr).await?;
            }
        }
    }

    let private_key_pem = order.finalize().await?;
    let cert_chain_pem = order.poll_certificate(&RetryPolicy::default()).await?;

    let openssl_cert = X509::from_pem(cert_chain_pem.as_bytes())?;
    let openssl_pkey = PKey::private_key_from_pem(private_key_pem.as_bytes())?;
    let pfx = Pkcs12::builder().pkey(&openssl_pkey).cert(&openssl_cert).build2("")?;
    let pfx_der = pfx.to_der()?;

    if let Some(parent) = FsPath::new(&config.key_path).parent()
        && !parent.as_os_str().is_empty()
        && !parent.exists()
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create key directory {}", parent.display()))?;
    }
    if let Some(parent) = FsPath::new(&config.cert_path).parent()
        && !parent.as_os_str().is_empty()
        && !parent.exists()
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create cert directory {}", parent.display()))?;
    }
    if let Some(parent) = FsPath::new(&config.pkcs12_path).parent()
        && !parent.as_os_str().is_empty()
        && !parent.exists()
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create PKCS#12 directory {}", parent.display()))?;
    }

    std::fs::write(&config.key_path, private_key_pem)
        .with_context(|| format!("failed to write key PEM {}", config.key_path))?;
    std::fs::write(&config.cert_path, cert_chain_pem)
        .with_context(|| format!("failed to write cert PEM {}", config.cert_path))?;
    std::fs::write(&config.pkcs12_path, pfx_der)
        .with_context(|| format!("failed to write PKCS#12 {}", config.pkcs12_path))?;
    tracing::info!("ACME certificate written to {}", config.cert_path);
    Ok(())
}

/// Handle ACME DNS-01 challenges for all pending authorizations using the
/// Cloudflare API.
async fn ensure_certificate_dns01(
    order: &mut instant_acme::Order,
    cloudflare_api_token: &str,
    cloudflare_zone_id: &str,
) -> anyhow::Result<()> {
    let client = Client::new();

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

        let record_id = create_resp.result.map(|v| v.id);
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
            if let Some(record_id) = record_id {
                if let Err(err) = client
                    .delete(format!(
                        "https://api.cloudflare.com/client/v4/zones/{cloudflare_zone_id}/dns_records/{record_id}"
                    ))
                    .bearer_auth(cloudflare_api_token)
                    .send()
                    .await
                {
                    tracing::warn!("failed to delete Cloudflare TXT challenge record: {err}");
                }
            }
            bail!(
                "dns challenge did not propagate in time for {}",
                challenge.identifier()
            );
        }

        challenge.set_ready().await?;

        if let Some(record_id) = record_id {
            if let Err(err) = client
                .delete(format!(
                    "https://api.cloudflare.com/client/v4/zones/{cloudflare_zone_id}/dns_records/{record_id}"
                ))
                .bearer_auth(cloudflare_api_token)
                .send()
                .await
            {
                tracing::warn!("failed to delete Cloudflare TXT challenge record: {err}");
            }
        }
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
