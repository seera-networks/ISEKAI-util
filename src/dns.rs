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

#[derive(Deserialize)]
struct CloudflareListRecordsResponse {
    success: bool,
    result: Vec<CloudflareListedRecord>,
}

#[derive(Deserialize)]
struct CloudflareListedRecord {
    id: String,
    content: String,
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

/// Remove the `A`/`AAAA` record of `host` that points at `addr`.
///
/// **The counterpart [`ensure_host_record`] never had.** That function only
/// ever creates: it returns early when a record with the same address exists
/// and otherwise POSTs a new one. So a name whose address *moves* keeps the old
/// record alongside the new, and an address taken out of service keeps
/// answering — for a name serving both families, the half a client prefers can
/// be the half that is gone.
///
/// **Matched on the address, not on the record type.** Deleting every `AAAA`
/// of a name would also remove records this zone's operator added by hand; the
/// caller knows which address it published, and that is the one this removes.
/// Content is compared as a parsed address rather than as text, because
/// `2001:0db8::9` and `2001:db8::9` are one address and two strings.
///
/// Returns how many records were removed. **Zero is not an error**: a
/// retraction that finds nothing has reached the state it was asking for, which
/// is what makes a retry safe.
pub async fn delete_host_record(
    host: &str,
    addr: &IpAddr,
    cloudflare_api_token: &str,
    cloudflare_zone_id: &str,
) -> anyhow::Result<usize> {
    let client = Client::new();
    let record_type = record_type_of(addr);

    // Scoped by name *and* type, so the answer is small and this cannot be
    // confused by another name's records. Cloudflare returns 100 per page by
    // default, which one name's `A`/`AAAA` set does not approach.
    let list_resp = client
        .get(format!(
            "https://api.cloudflare.com/client/v4/zones/{cloudflare_zone_id}/dns_records"
        ))
        .query(&[("type", record_type), ("name", host)])
        .bearer_auth(cloudflare_api_token)
        .send()
        .await
        .with_context(|| format!("failed to list Cloudflare {record_type} records for {host}"))?
        .error_for_status()?
        .json::<CloudflareListRecordsResponse>()
        .await
        .with_context(|| format!("failed to read Cloudflare's {record_type} list for {host}"))?;
    if !list_resp.success {
        bail!("failed to list Cloudflare {record_type} records for {host}");
    }

    let mut deleted = 0;
    for record in list_resp
        .result
        .iter()
        .filter(|record| content_is(&record.content, addr))
    {
        client
            .delete(format!(
                "https://api.cloudflare.com/client/v4/zones/{cloudflare_zone_id}/dns_records/{}",
                record.id
            ))
            .bearer_auth(cloudflare_api_token)
            .send()
            .await
            .with_context(|| {
                format!(
                    "failed to delete Cloudflare {record_type} record {}",
                    record.id
                )
            })?
            .error_for_status()?;
        tracing::debug!("deleted Cloudflare {record_type} record for {host} with value {addr}");
        deleted += 1;
    }
    Ok(deleted)
}

/// `A` for IPv4, `AAAA` for IPv6 — the one place that mapping is written.
fn record_type_of(addr: &IpAddr) -> &'static str {
    if addr.is_ipv4() { "A" } else { "AAAA" }
}

/// Whether a record's content is this address.
///
/// **Parsed, not compared as text.** Cloudflare returns the address in its own
/// normalisation, and an IPv6 address has many spellings; a string comparison
/// would leave the record this was asked to remove in place and report that it
/// removed nothing, which reads as "already gone".
fn content_is(content: &str, addr: &IpAddr) -> bool {
    content.trim().parse::<IpAddr>().ok() == Some(*addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_get_name_servers() {
        let name_servers = get_name_servers("edge.isekai.tools").await.unwrap();
        assert!(!name_servers.is_empty());
    }

    #[test]
    fn a_record_for_v4_and_aaaa_for_v6() {
        assert_eq!(record_type_of(&"8.8.8.8".parse().unwrap()), "A");
        assert_eq!(
            record_type_of(&"2001:4860:4860::8888".parse().unwrap()),
            "AAAA"
        );
    }

    /// **One address, many spellings.** A string comparison would miss the
    /// record it was asked to remove and then report that there was nothing to
    /// remove — indistinguishable from a retraction that had already happened.
    #[test]
    fn content_matches_whatever_spelling_the_api_returned() {
        let addr: IpAddr = "2001:db8::9".parse().unwrap();
        for content in [
            "2001:db8::9",
            "2001:0db8::9",
            "2001:0db8:0000:0000:0000:0000:0000:0009",
            " 2001:db8::9 ",
        ] {
            assert!(content_is(content, &addr), "did not match {content:?}");
        }
        assert!(!content_is("2001:db8::10", &addr));
        // An IPv4 record never matches an IPv6 address, whatever the text.
        assert!(!content_is("8.8.8.8", &addr));
    }

    /// Content that is not an address at all — a `CNAME` target reached by a
    /// mistaken call, say — matches nothing rather than panicking.
    #[test]
    fn content_that_is_not_an_address_matches_nothing() {
        let addr: IpAddr = "8.8.8.8".parse().unwrap();
        assert!(!content_is("relay.example.com", &addr));
        assert!(!content_is("", &addr));
    }
}
