use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use clap::Parser;
use csv::Writer;
use log::{info, warn};
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use serde_derive::Deserialize;
use serde_json::Value;
use std::collections::{BTreeSet, HashMap};
use std::time::{Duration, Instant};
use tokio::time::sleep;

#[derive(Parser, Debug, Clone)]
pub struct UalGraphCliArgs {
    #[arg(long, help = "Tenant ID of the Azure AD app registration.")]
    pub tenant_id: String,

    #[arg(long, help = "Client ID of the Azure AD app registration.")]
    pub client_id: String,

    #[arg(long, help = "Client secret of the Azure AD app registration.")]
    pub secret_key: String,

    #[arg(
        long,
        help = "Start of export window in RFC3339 format (e.g. 2026-01-01T00:00:00Z)."
    )]
    pub start_time: String,

    #[arg(
        long,
        help = "End of export window in RFC3339 format (e.g. 2026-01-01T12:00:00Z)."
    )]
    pub end_time: String,

    #[arg(long, default_value = "json", value_parser = ["json", "csv"], help = "Output format.")]
    pub format: String,

    #[arg(
        long,
        default_value = "ualgraph_export.json",
        help = "Output file path."
    )]
    pub output: String,

    #[arg(
        long,
        required = false,
        help = "Optional Graph filter string for the query."
    )]
    pub filter: Option<String>,

    #[arg(long, default_value_t = 10, help = "Polling interval in seconds.")]
    pub poll_interval_seconds: u64,

    #[arg(long, default_value_t = 30, help = "Polling timeout in minutes.")]
    pub timeout_minutes: u64,
}

#[derive(Deserialize)]
struct GraphAuthResult {
    access_token: String,
}

pub async fn export_ualgraph(args: UalGraphCliArgs) -> Result<()> {
    let start = normalize_rfc3339_utc(&args.start_time)?;
    let end = normalize_rfc3339_utc(&args.end_time)?;

    if start >= end {
        return Err(anyhow!("start-time must be before end-time"));
    }

    info!("Authenticating to Microsoft Graph.");
    let token = get_graph_token(&args).await?;
    let headers = build_graph_headers(&token)?;
    let client = reqwest::Client::new();

    info!("Creating UALGraph query.");
    let mut body = serde_json::json!({
        "displayName": format!("OfficeAuditLogCollector {}", Utc::now().to_rfc3339()),
        "filterStartDateTime": start,
        "filterEndDateTime": end,
    });
    if let Some(filter) = args.filter.as_ref() {
        body["query"] = Value::String(filter.clone());
    }

    let response = client
        .post("https://graph.microsoft.com/beta/security/auditLog/queries")
        .headers(headers.clone())
        .json(&body)
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let text = response.text().await.unwrap_or_else(|_| "".to_string());
        return Err(anyhow!(
            "Graph query creation failed ({}): {}",
            status,
            text
        ));
    }

    let create_headers = response.headers().clone();
    let create_json = response.json::<Value>().await?;

    let query_id = create_json
        .get("id")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| anyhow!("Graph query creation response is missing id"))?;

    let poll_url = create_headers
        .get("operation-location")
        .or_else(|| create_headers.get("location"))
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .unwrap_or_else(|| {
            format!(
                "https://graph.microsoft.com/beta/security/auditLog/queries/{}",
                query_id
            )
        });

    info!("Polling UALGraph query {}.", query_id);
    let final_query = poll_query_until_ready(
        &client,
        &headers,
        &poll_url,
        args.poll_interval_seconds,
        args.timeout_minutes,
    )
    .await?;

    let output_bytes = if args.format == "csv" {
        if let Some(csv_bytes) =
            try_download_csv(&client, &headers, &final_query, &query_id).await?
        {
            csv_bytes
        } else {
            let records = download_records_json(&client, &headers, &final_query, &query_id).await?;
            build_csv_bytes(&records)?
        }
    } else {
        let records = download_records_json(&client, &headers, &final_query, &query_id).await?;
        serde_json::to_vec_pretty(&records)?
    };

    std::fs::write(&args.output, output_bytes)?;
    info!(
        "UALGraph export completed. Saved output to {}.",
        args.output
    );
    Ok(())
}

fn normalize_rfc3339_utc(raw: &str) -> Result<String> {
    let parsed = DateTime::parse_from_rfc3339(raw)
        .map_err(|e| anyhow!("invalid RFC3339 datetime '{}': {}", raw, e))?;
    Ok(parsed
        .with_timezone(&Utc)
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
}

async fn get_graph_token(args: &UalGraphCliArgs) -> Result<String> {
    let auth_url = format!(
        "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
        args.tenant_id
    );
    let params = [
        ("grant_type", "client_credentials"),
        ("client_id", args.client_id.as_str()),
        ("client_secret", args.secret_key.as_str()),
        ("scope", "https://graph.microsoft.com/.default"),
    ];
    let response = reqwest::Client::new()
        .post(auth_url)
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .form(&params)
        .send()
        .await?;
    if !response.status().is_success() {
        let status = response.status();
        let text = response.text().await.unwrap_or_else(|_| "".to_string());
        return Err(anyhow!(
            "Graph authentication failed ({}): {}",
            status,
            text
        ));
    }
    let auth = response.json::<GraphAuthResult>().await?;
    Ok(auth.access_token)
}

fn build_graph_headers(token: &str) -> Result<HeaderMap> {
    let mut headers = HeaderMap::new();
    let bearer = format!("Bearer {}", token);
    headers.insert(AUTHORIZATION, HeaderValue::from_str(&bearer)?);
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    Ok(headers)
}

async fn poll_query_until_ready(
    client: &reqwest::Client,
    headers: &HeaderMap,
    poll_url: &str,
    poll_interval_seconds: u64,
    timeout_minutes: u64,
) -> Result<Value> {
    let deadline = Instant::now() + Duration::from_secs(timeout_minutes.saturating_mul(60));
    loop {
        if Instant::now() >= deadline {
            return Err(anyhow!(
                "Polling timed out after {} minute(s)",
                timeout_minutes
            ));
        }

        let response = client.get(poll_url).headers(headers.clone()).send().await?;
        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_else(|_| "".to_string());
            return Err(anyhow!("Graph poll failed ({}): {}", status, text));
        }
        let query = response.json::<Value>().await?;
        let status = query
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_lowercase();

        if status == "succeeded" || status == "completed" {
            return Ok(query);
        }
        if status == "failed" || status == "cancelled" {
            let reason = query
                .get("failureReason")
                .and_then(Value::as_str)
                .unwrap_or("unknown error");
            return Err(anyhow!("UALGraph query failed: {}", reason));
        }

        sleep(Duration::from_secs(poll_interval_seconds.max(1))).await;
    }
}

async fn try_download_csv(
    client: &reqwest::Client,
    headers: &HeaderMap,
    query: &Value,
    query_id: &str,
) -> Result<Option<Vec<u8>>> {
    for url in result_urls(query, query_id) {
        let response = match client.get(&url).headers(headers.clone()).send().await {
            Ok(resp) => resp,
            Err(e) => {
                warn!("Could not download CSV from {}: {}", url, e);
                continue;
            }
        };
        if !response.status().is_success() {
            continue;
        }
        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_lowercase();
        if content_type.contains("text/csv") || content_type.contains("application/csv") {
            return Ok(Some(response.bytes().await?.to_vec()));
        }
    }
    Ok(None)
}

async fn download_records_json(
    client: &reqwest::Client,
    headers: &HeaderMap,
    query: &Value,
    query_id: &str,
) -> Result<Vec<HashMap<String, Value>>> {
    if let Some(records) = parse_records(query) {
        return Ok(records);
    }

    for url in result_urls(query, query_id) {
        let response = match client.get(&url).headers(headers.clone()).send().await {
            Ok(resp) => resp,
            Err(e) => {
                warn!("Could not download records from {}: {}", url, e);
                continue;
            }
        };
        if !response.status().is_success() {
            continue;
        }
        let value = match response.json::<Value>().await {
            Ok(v) => v,
            Err(e) => {
                warn!("Failed to parse JSON records from {}: {}", url, e);
                continue;
            }
        };
        if let Some(records) = parse_records(&value) {
            return Ok(records);
        }
    }

    Err(anyhow!("Could not locate any records in query response"))
}

fn result_urls(query: &Value, query_id: &str) -> Vec<String> {
    let mut urls = Vec::new();
    for key in [
        "downloadUrl",
        "contentUrl",
        "resultUrl",
        "recordsUrl",
        "resultsUrl",
    ] {
        if let Some(url) = query.get(key).and_then(Value::as_str) {
            urls.push(url.to_string());
        }
    }
    urls.push(format!(
        "https://graph.microsoft.com/beta/security/auditLog/queries/{}/records",
        query_id
    ));
    urls
}

fn parse_records(value: &Value) -> Option<Vec<HashMap<String, Value>>> {
    if let Some(items) = value.as_array() {
        return Some(json_array_to_records(items));
    }
    let object = value.as_object()?;
    for key in ["records", "value"] {
        if let Some(items) = object.get(key).and_then(Value::as_array) {
            return Some(json_array_to_records(items));
        }
    }
    None
}

fn json_array_to_records(items: &[Value]) -> Vec<HashMap<String, Value>> {
    items
        .iter()
        .filter_map(|item| item.as_object().cloned())
        .map(|obj| obj.into_iter().collect::<HashMap<String, Value>>())
        .collect()
}

fn build_csv_bytes(records: &[HashMap<String, Value>]) -> Result<Vec<u8>> {
    let mut columns = BTreeSet::new();
    for record in records {
        for key in record.keys() {
            columns.insert(key.to_string());
        }
    }
    let ordered_columns = columns.into_iter().collect::<Vec<String>>();
    let mut writer = Writer::from_writer(Vec::<u8>::new());
    if !ordered_columns.is_empty() {
        writer.write_record(&ordered_columns)?;
    }
    for record in records {
        let row = ordered_columns
            .iter()
            .map(|key| {
                record
                    .get(key)
                    .map(Value::to_string)
                    .unwrap_or_else(|| "".to_string())
            })
            .collect::<Vec<String>>();
        writer.write_record(row)?;
    }
    Ok(writer.into_inner()?)
}

#[cfg(test)]
mod tests {
    use super::{normalize_rfc3339_utc, parse_records};
    use serde_json::json;

    #[test]
    fn normalizes_datetime_to_utc() {
        let normalized = normalize_rfc3339_utc("2026-01-01T10:15:00+02:00").unwrap();
        assert_eq!(normalized, "2026-01-01T08:15:00Z");
    }

    #[test]
    fn parses_records_from_value_property() {
        let body = json!({
            "value": [
                { "id": "1", "activity": "A" },
                { "id": "2", "activity": "B" }
            ]
        });
        let records = parse_records(&body).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].get("id").unwrap(), "1");
    }
}
