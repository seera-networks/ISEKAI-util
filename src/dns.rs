use anyhow::{Context, bail};
use hickory_net::runtime::TokioRuntimeProvider;
use hickory_resolver::{
    Resolver,
    config::{NameServerConfig, ResolverConfig, ResolverOpts},
    proto::rr::RecordType,
};
use reqwest::Client;
use serde::Deserialize;
use serde_json::json;
use std::net::{IpAddr, SocketAddr};

#[derive(Deserialize)]
struct CloudflareCreateRecordResponse {
    success: bool,
    _result: Option<CloudflareRecordResult>,
}

#[derive(Deserialize)]
struct CloudflareRecordResult {
    _id: String,
}

pub async fn get_name_servers(host: &str) -> anyhow::Result<Vec<IpAddr>> {
    let resolver = Resolver::builder_tokio()?.build()?;
    let mut parts: Vec<&str> = host.split('.').collect();

    let mut name_servers = Vec::new();
    while parts.len() >= 2 {
        let candidate = parts.join(".");

        match resolver
            .lookup(format!("{candidate}."), RecordType::NS)
            .await
        {
            Ok(lookup) => {
                if lookup.answers().is_empty() {
                    parts.remove(0);
                    continue;
                }

                for record in lookup.answers() {
                    let ns = record.data.to_string();
                    let ips = resolver.lookup_ip(ns).await?;
                    for ip in ips.iter() {
                        name_servers.push(ip);
                    }
                }
                return Ok(name_servers);
            }
            Err(_) => {
                parts.remove(0);
            }
        }
    }
    Ok(name_servers)
}

pub async fn ensure_host_record(
    host: &str,
    addr: &SocketAddr,
    cloudflare_api_token: &str,
    cloudflare_zone_id: &str,
) -> anyhow::Result<()> {
    let client = Client::new();

    let ips = get_name_servers(host)
        .await
        .with_context(|| format!("failed to get NS servers for {}", host))?;

    let mut ns_configs = Vec::new();
    for ip in ips {
        tracing::debug!("querying A Record propagation via NS server {ip}");
        let ns_config = NameServerConfig::udp_and_tcp(ip);
        ns_configs.push(ns_config);
    }
    let resolver_config = ResolverConfig::from_parts(None, vec![], ns_configs);
    let mut resolver_opts = ResolverOpts::default();
    resolver_opts.negative_max_ttl = Some(std::time::Duration::from_secs(0));
    let resolver = Resolver::builder_with_config(resolver_config, TokioRuntimeProvider::new())
        .with_options(resolver_opts)
        .build()?;

    let record_type = if addr.is_ipv4() {
        RecordType::A
    } else {
        RecordType::AAAA
    };
    let lookup = resolver.lookup(format!("{host}."), record_type).await;
    if let Ok(lookup) = lookup
        && lookup.answers().iter().any(|record| {
            tracing::debug!("existing DNS record for {host}: {}", record.to_string());
            record.to_string().contains(&addr.ip().to_string())
        })
    {
        // Record already exists, nothing to do.
        return Ok(());
    }

    let record_type = if addr.is_ipv4() { "A" } else { "AAAA" };
    let create_resp = client
        .post(format!(
            "https://api.cloudflare.com/client/v4/zones/{cloudflare_zone_id}/dns_records"
        ))
        .bearer_auth(cloudflare_api_token)
        .json(&json!({
            "type": record_type,
            "name": host,
            "content": addr.ip().to_string(),
            "ttl": 3600,
            "proxied": false
        }))
        .send()
        .await?
        .error_for_status()?
        .json::<CloudflareCreateRecordResponse>()
        .await?;
    if !create_resp.success {
        bail!("failed to create Cloudflare {} record", record_type);
    }
    tracing::debug!(
        "created Cloudflare {} record for {} with value {}",
        record_type,
        host,
        addr.ip()
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_get_name_servers() {
        let name_servers = get_name_servers("edge.isekai.tools").await.unwrap();
        assert!(!name_servers.is_empty());
    }
}
