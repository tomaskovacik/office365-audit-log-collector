use crate::data_structures::{ArbitraryJson, AuthResult, CliArgs};
use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use log::{debug, error, info, warn};
use reqwest::header::{HeaderMap, AUTHORIZATION, CONTENT_TYPE};
use reqwest::Url;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tokio::time::sleep;

const POLL_INTERVAL_SECS: u64 = 2;
const POLL_ATTEMPTS: usize = 60;
const DEFAULT_EXPIRATION_DAYS: i64 = 30;
const RATE_LIMIT_RETRY_ATTEMPTS: usize = 5;
const RATE_LIMIT_RETRY_SLEEP_SECS: u64 = 600;
const SERVER_ERROR_RETRY_ATTEMPTS: usize = 3;
const SERVER_ERROR_RETRY_SLEEP_SECS: u64 = 60;
pub const DEFAULT_QUERY_TIMEOUT_RETRIES: usize = 3;
/// Maximum number of records to request per page when fetching UAL records from the
/// Microsoft Graph API.  Microsoft supports up to 50,000 items per page for the
/// `security/auditLog/queries/{id}/records` endpoint, matching the behaviour of the
/// reference PowerShell script (Get-UAL.ps1 `$MaxItemsPerInterval = 50000`).
pub(crate) const UAL_RECORDS_PAGE_SIZE: usize = 50000;

/// Maximum concurrent connections to the Graph beta endpoint (Microsoft limit).
const MAX_CONCURRENT_CONNECTIONS: usize = 4;
/// Maximum POST requests per rate-limit window (Microsoft limit: 25/10 s).
const MAX_POST_PER_WINDOW: u32 = 25;
/// Maximum GET requests per rate-limit window (Microsoft limit: 350/10 s).
const MAX_GET_PER_WINDOW: u32 = 350;
/// Duration of the sliding rate-limit window in seconds.
const RATE_LIMIT_WINDOW_SECS: u64 = 10;

/// Token-bucket rate limiter that tracks POST and GET request counts within a
/// rolling 10-second window.  Each call to `claim_post` / `claim_get` either
/// returns immediately (quota available) or returns a `Duration` that the
/// caller must sleep before sending the request.
struct GraphRateLimiter {
    post_window_start: Instant,
    post_count: u32,
    get_window_start: Instant,
    get_count: u32,
}

impl GraphRateLimiter {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            post_window_start: now,
            post_count: 0,
            get_window_start: now,
            get_count: 0,
        }
    }

    /// Claim one POST slot.  Returns the duration to sleep before sending.
    fn claim_post(&mut self) -> Duration {
        Self::claim_slot(
            &mut self.post_count,
            &mut self.post_window_start,
            MAX_POST_PER_WINDOW,
        )
    }

    /// Claim one GET slot.  Returns the duration to sleep before sending.
    fn claim_get(&mut self) -> Duration {
        Self::claim_slot(
            &mut self.get_count,
            &mut self.get_window_start,
            MAX_GET_PER_WINDOW,
        )
    }

    fn claim_slot(count: &mut u32, window_start: &mut Instant, max: u32) -> Duration {
        let now = Instant::now();
        let elapsed = now.duration_since(*window_start);
        let window = Duration::from_secs(RATE_LIMIT_WINDOW_SECS);

        if elapsed >= window {
            // Start a fresh window.
            *window_start = now;
            *count = 1;
            return Duration::ZERO;
        }

        if *count < max {
            *count += 1;
            return Duration::ZERO;
        }

        // Window is exhausted — return the remaining time without modifying
        // state.  After the caller sleeps for this duration the next invocation
        // will observe elapsed >= window and start a fresh window naturally.
        window - elapsed
    }
}
const UAL_GRAPH_CONTENT_TYPE: &str = "UALGraph";
const ENTRA_SIGNIN_CONTENT_TYPE: &str = "EntraID.SignIns";
const ENTRA_AUDIT_CONTENT_TYPE: &str = "EntraID.DirectoryAudits";
const EXCHANGE_MAILBOX_GRAPH_CONTENT_TYPE: &str = "ExchangeMailbox.Graph";
const INTUNE_CONTENT_TYPE: &str = "Intune";

/// Record type filters used when querying the UAL endpoint for Exchange Mailbox events.
/// Uses the valid `auditLogRecordType` enum values from the Microsoft Graph Security API:
/// `exchangeItem` (per-item mailbox operations), `exchangeItemGroup` (group mailbox item
/// operations), and `exchangeItemAggregated` (aggregated Exchange item events).
pub(crate) const EXCHANGE_MAILBOX_RECORD_TYPE_FILTERS: &[&str] =
    &["exchangeItem", "exchangeItemGroup", "exchangeItemAggregated"];

#[derive(Clone)]
pub struct GraphUALConnection {
    pub args: CliArgs,
    pub headers: HeaderMap,
    pub retries: usize,
    /// Management client used for login, query creation (POST) and query status polling (GET).
    /// Limited to a single idle connection per host so that polling requests are naturally
    /// serialised and do not overwhelm Microsoft's per-tenant rate limits.
    client: reqwest::Client,
    /// Fetch client used exclusively for downloading audit-log records after a query succeeds.
    /// Keeps up to `MAX_CONCURRENT_CONNECTIONS` idle connections per host so that large
    /// paginated result sets can be retrieved efficiently.
    fetch_client: reqwest::Client,
    /// Shared token-bucket rate limiter for the Graph beta endpoint.
    rate_limiter: Arc<Mutex<GraphRateLimiter>>,
}

#[derive(Clone)]
pub struct GraphLogRecord {
    pub content_type: String,
    pub content_id: String,
    pub expiration: String,
    pub log: ArbitraryJson,
}

pub async fn get_graph_connection(args: CliArgs, retries: usize) -> Result<GraphUALConnection> {
    // Management client: single idle connection per host to keep polling requests serialised
    // and avoid hitting Microsoft's per-tenant rate limits during the status-poll phase.
    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(1)
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());
    // Fetch client: larger connection pool for downloading paginated record sets efficiently.
    let fetch_client = reqwest::Client::builder()
        .pool_max_idle_per_host(MAX_CONCURRENT_CONNECTIONS)
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());
    let mut api = GraphUALConnection {
        args,
        headers: HeaderMap::new(),
        retries,
        client,
        fetch_client,
        rate_limiter: Arc::new(Mutex::new(GraphRateLimiter::new())),
    };
    api.login().await?;
    Ok(api)
}

impl GraphUALConnection {
    pub async fn login(&mut self) -> Result<()> {
        info!("Logging in to Microsoft Graph API.");
        let auth_url = format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
            self.args.tenant_id
        );
        let scope = "https://graph.microsoft.com/.default";
        let params = [
            ("grant_type", "client_credentials"),
            ("client_id", &self.args.client_id),
            ("client_secret", &self.args.secret_key),
            ("scope", scope),
        ];
        self.headers.insert(
            CONTENT_TYPE,
            "application/x-www-form-urlencoded".parse().unwrap(),
        );
        let response = self.client
            .post(auth_url)
            .headers(self.headers.clone())
            .form(&params)
            .send()
            .await?;
        if !response.status().is_success() {
            let text = response.text().await?;
            let msg = format!("Received error response to Graph API login: {}", text);
            error!("{}", msg);
            return Err(anyhow!("{}", msg));
        }
        let json = response.json::<AuthResult>().await?;
        let token = format!("bearer {}", json.access_token);
        self.headers.insert(AUTHORIZATION, token.parse().unwrap());
        info!("Successfully logged in to Microsoft Graph API.");
        Ok(())
    }

    /// Wait until a POST request slot is available within the rate-limit window.
    async fn wait_for_post_rate_limit(&self) {
        let sleep_duration = self.rate_limiter.lock().await.claim_post();
        if !sleep_duration.is_zero() {
            info!(
                "Graph API POST rate limit reached, waiting {} ms before next request",
                sleep_duration.as_millis()
            );
            sleep(sleep_duration).await;
        }
    }

    /// Wait until a GET request slot is available within the rate-limit window.
    async fn wait_for_get_rate_limit(&self) {
        let sleep_duration = self.rate_limiter.lock().await.claim_get();
        if !sleep_duration.is_zero() {
            info!(
                "Graph API GET rate limit reached, waiting {} ms before next request",
                sleep_duration.as_millis()
            );
            sleep(sleep_duration).await;
        }
    }

    pub async fn collect_logs(
        &self,
        runs: &Vec<(String, String)>,
        known_blobs: &HashMap<String, String>,
        skip_known_logs: bool,
    ) -> Result<Vec<GraphLogRecord>> {
        let mut collected = Vec::new();
        for (start_time, end_time) in runs {
            info!(
                "Collecting Graph UAL logs for time range {} - {}",
                start_time, end_time
            );
            let mut last_err = anyhow!("Graph UAL query timed out after {} attempts", self.retries);
            let mut succeeded = false;
            for attempt in 0..self.retries {
                if attempt > 0 {
                    warn!(
                        "Graph UAL query timed out, retrying ({}/{})",
                        attempt, self.retries - 1
                    );
                }
                let query_id = self.start_query(start_time, end_time).await?;
                match self.wait_for_query_completion(&query_id).await {
                    Ok(()) => {
                        let mut query_logs = self
                            .get_query_records(&query_id, known_blobs, skip_known_logs)
                            .await?;
                        info!(
                            "Successfully collected {} Graph UAL records for time range {} - {}",
                            query_logs.len(),
                            start_time,
                            end_time
                        );
                        collected.append(&mut query_logs);
                        succeeded = true;
                        break;
                    }
                    Err(e) if is_query_timeout_error(&e) => {
                        last_err = e;
                    }
                    Err(e) => return Err(e),
                }
            }
            if !succeeded {
                return Err(last_err);
            }
        }
        Ok(collected)
    }

    pub async fn collect_entra_directory_audit_logs(
        &self,
        runs: &Vec<(String, String)>,
        categories: &[String],
        known_blobs: &HashMap<String, String>,
        skip_known_logs: bool,
    ) -> Result<Vec<GraphLogRecord>> {
        let mut collected = Vec::new();

        for (start_time, end_time) in runs {
            info!(
                "Collecting Entra ID directory audit logs for time range {} - {}",
                start_time, end_time
            );
            let run_start_len = collected.len();
            let mut next_page = Some(build_directory_audit_url(start_time, end_time, categories)?);
            while let Some(url) = next_page {
                debug!("Fetching Entra ID directory audit records page");
                let json = self
                    .get_json_with_retry(&self.fetch_client, &url, "Graph Entra ID audit request failed")
                    .await?;
                let records = json
                    .get("value")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();
                debug!(
                    "Retrieved {} Entra ID directory audit records on this page",
                    records.len()
                );
                for record in records {
                    let map = record.as_object().cloned();
                    if map.is_none() {
                        warn!("Directory audit record was not an object, skipping.");
                        continue;
                    }
                    let mut log: ArbitraryJson = map.unwrap().into_iter().collect();
                    normalize_creation_time(&mut log);
                    if let Some(new_record) = create_graph_log_record(
                        ENTRA_AUDIT_CONTENT_TYPE,
                        log,
                        known_blobs,
                        skip_known_logs,
                    ) {
                        collected.push(new_record);
                    }
                }
                next_page = json
                    .get("@odata.nextLink")
                    .and_then(|v| v.as_str())
                    .map(|v| v.to_string());
            }
            info!(
                "Successfully collected {} Entra ID directory audit records for time range {} - {}",
                collected.len() - run_start_len,
                start_time,
                end_time
            );
        }
        Ok(collected)
    }

    pub async fn collect_entra_signin_logs(
        &self,
        runs: &Vec<(String, String)>,
        known_blobs: &HashMap<String, String>,
        skip_known_logs: bool,
    ) -> Result<Vec<GraphLogRecord>> {
        let mut collected = Vec::new();

        for (start_time, end_time) in runs {
            info!(
                "Collecting Entra ID sign-in logs for time range {} - {}",
                start_time, end_time
            );
            let run_start_len = collected.len();
            let mut next_page = Some(build_signin_url(start_time, end_time)?);
            while let Some(url) = next_page {
                debug!("Fetching Entra ID sign-in records page");
                let json = self
                    .get_json_with_retry(&self.fetch_client, &url, "Graph Entra ID sign-ins request failed")
                    .await?;
                let records = json
                    .get("value")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();
                debug!(
                    "Retrieved {} Entra ID sign-in records on this page",
                    records.len()
                );
                for record in records {
                    let map = record.as_object().cloned();
                    if map.is_none() {
                        warn!("Sign-in record was not an object, skipping.");
                        continue;
                    }
                    let mut log: ArbitraryJson = map.unwrap().into_iter().collect();
                    normalize_creation_time(&mut log);
                    if let Some(new_record) = create_graph_log_record(
                        ENTRA_SIGNIN_CONTENT_TYPE,
                        log,
                        known_blobs,
                        skip_known_logs,
                    ) {
                        collected.push(new_record);
                    }
                }
                next_page = json
                    .get("@odata.nextLink")
                    .and_then(|v| v.as_str())
                    .map(|v| v.to_string());
            }
            info!(
                "Successfully collected {} Entra ID sign-in records for time range {} - {}",
                collected.len() - run_start_len,
                start_time,
                end_time
            );
        }
        Ok(collected)
    }

    /// Collect Exchange Mailbox Audit Logs via the Microsoft Graph UAL beta endpoint,
    /// filtering for `exchangeItem`, `exchangeItemGroup`, and `exchangeItemAggregated` record
    /// types. These are the valid `auditLogRecordType` enum values that cover Exchange mailbox
    /// item-level operations (read, send, delete, etc.).
    ///
    /// Required Graph permission: `AuditLogsQuery.Read.All`
    pub async fn collect_exchange_mailbox_logs(
        &self,
        runs: &Vec<(String, String)>,
        known_blobs: &HashMap<String, String>,
        skip_known_logs: bool,
    ) -> Result<Vec<GraphLogRecord>> {
        let mut collected = Vec::new();
        for (start_time, end_time) in runs {
            info!(
                "Collecting Exchange Mailbox Graph logs for time range {} - {}",
                start_time, end_time
            );
            let mut last_err = anyhow!("Graph UAL query timed out after {} attempts", self.retries);
            let mut succeeded = false;
            for attempt in 0..self.retries {
                if attempt > 0 {
                    warn!(
                        "Graph UAL query timed out, retrying ({}/{})",
                        attempt, self.retries - 1
                    );
                }
                let query_id = self
                    .start_query_with_record_types(
                        start_time,
                        end_time,
                        EXCHANGE_MAILBOX_RECORD_TYPE_FILTERS,
                    )
                    .await?;
                match self.wait_for_query_completion(&query_id).await {
                    Ok(()) => {
                        let mut query_logs = self
                            .get_exchange_mailbox_records(&query_id, known_blobs, skip_known_logs)
                            .await?;
                        info!(
                            "Successfully collected {} Exchange Mailbox Graph records for time range {} - {}",
                            query_logs.len(),
                            start_time,
                            end_time
                        );
                        collected.append(&mut query_logs);
                        succeeded = true;
                        break;
                    }
                    Err(e) if is_query_timeout_error(&e) => {
                        last_err = e;
                    }
                    Err(e) => return Err(e),
                }
            }
            if !succeeded {
                return Err(last_err);
            }
        }
        Ok(collected)
    }

    async fn get_exchange_mailbox_records(
        &self,
        query_id: &str,
        known_blobs: &HashMap<String, String>,
        skip_known_logs: bool,
    ) -> Result<Vec<GraphLogRecord>> {
        let mut next_page = Some(format!(
            "https://graph.microsoft.com/beta/security/auditLog/queries/{}/records?$top={}",
            query_id, UAL_RECORDS_PAGE_SIZE
        ));
        let mut results = Vec::new();

        while let Some(url) = next_page {
            debug!(
                "Fetching Exchange Mailbox Graph records page for query {}",
                query_id
            );
            let json = self
                .get_json_with_retry(&self.fetch_client, &url, "Exchange Mailbox Graph UAL records request failed")
                .await?;
            let records = json
                .get("value")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            debug!(
                "Retrieved {} Exchange Mailbox Graph records on this page for query {}",
                records.len(),
                query_id
            );

            for record in records {
                let map = record.as_object().cloned();
                if map.is_none() {
                    warn!("Exchange Mailbox Graph record was not an object, skipping.");
                    continue;
                }
                let mut log: ArbitraryJson = map.unwrap().into_iter().collect();
                normalize_creation_time(&mut log);
                if let Some(new_record) = create_graph_log_record(
                    EXCHANGE_MAILBOX_GRAPH_CONTENT_TYPE,
                    log,
                    known_blobs,
                    skip_known_logs,
                ) {
                    results.push(new_record);
                }
            }
            next_page = json
                .get("@odata.nextLink")
                .and_then(|v| v.as_str())
                .map(|v| v.to_string());
        }
        debug!(
            "Total Exchange Mailbox Graph records retrieved for query {}: {}",
            query_id,
            results.len()
        );
        Ok(results)
    }

    async fn start_query(&self, start_time: &str, end_time: &str) -> Result<String> {
        self.start_query_with_record_types(start_time, end_time, &[]).await
    }

    /// Collect Intune audit events via the Microsoft Graph deviceManagement endpoint.
    ///
    /// Required Graph permission: `DeviceManagementApps.Read.All` or
    /// `DeviceManagementConfiguration.Read.All`
    pub async fn collect_intune_logs(
        &self,
        runs: &Vec<(String, String)>,
        known_blobs: &HashMap<String, String>,
        skip_known_logs: bool,
    ) -> Result<Vec<GraphLogRecord>> {
        let mut collected = Vec::new();

        for (start_time, end_time) in runs {
            info!(
                "Collecting Intune audit logs for time range {} - {}",
                start_time, end_time
            );
            let run_start_len = collected.len();
            let mut next_page = Some(build_intune_url(start_time, end_time)?);
            while let Some(url) = next_page {
                debug!("Fetching Intune audit records page");
                let json = self
                    .get_json_with_retry(&self.fetch_client, &url, "Graph Intune audit events request failed")
                    .await?;
                let records = json
                    .get("value")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();
                debug!(
                    "Retrieved {} Intune audit records on this page",
                    records.len()
                );
                for record in records {
                    let map = record.as_object().cloned();
                    if map.is_none() {
                        warn!("Intune audit record was not an object, skipping.");
                        continue;
                    }
                    let mut log: ArbitraryJson = map.unwrap().into_iter().collect();
                    normalize_creation_time(&mut log);
                    if let Some(new_record) = create_graph_log_record(
                        INTUNE_CONTENT_TYPE,
                        log,
                        known_blobs,
                        skip_known_logs,
                    ) {
                        collected.push(new_record);
                    }
                }
                next_page = json
                    .get("@odata.nextLink")
                    .and_then(|v| v.as_str())
                    .map(|v| v.to_string());
            }
            info!(
                "Successfully collected {} Intune audit records for time range {} - {}",
                collected.len() - run_start_len,
                start_time,
                end_time
            );
        }
        Ok(collected)
    }

    /// Start a UAL audit-log query, optionally filtered to specific record types.
    /// Passing an empty slice means no record-type filter (all types returned).
    async fn start_query_with_record_types(
        &self,
        start_time: &str,
        end_time: &str,
        record_type_filters: &[&str],
    ) -> Result<String> {
        let url = "https://graph.microsoft.com/beta/security/auditLog/queries";
        let mut body = json!({
            "displayName": format!("GraphUALCollector-{}-{}", start_time, end_time),
            "filterStartDateTime": start_time,
            "filterEndDateTime": end_time
        });
        if !record_type_filters.is_empty() {
            body["recordTypeFilters"] = json!(record_type_filters);
            debug!(
                "Starting Graph UAL query for time range {} - {} with record type filters: {:?}",
                start_time, end_time, record_type_filters
            );
        } else {
            debug!(
                "Starting Graph UAL query for time range {} - {}",
                start_time, end_time
            );
        }
        let mut last_error = String::new();
        for attempt in 0..RATE_LIMIT_RETRY_ATTEMPTS {
            self.wait_for_post_rate_limit().await;
            let response = self.client
                .post(url)
                .headers(self.headers.clone())
                .json(&body)
                .send()
                .await?;
            let status = response.status();
            if !status.is_success() {
                let retry_after = extract_retry_after_secs(&response);
                let text = response.text().await?;
                if is_rate_limited(status.as_u16(), &text) {
                    last_error = text;
                    if attempt + 1 < RATE_LIMIT_RETRY_ATTEMPTS {
                        let wait = retry_after.unwrap_or(RATE_LIMIT_RETRY_SLEEP_SECS);
                        warn!(
                            "Graph API rate limited, waiting {} seconds before retry ({}/{})",
                            wait, attempt + 1, RATE_LIMIT_RETRY_ATTEMPTS - 1
                        );
                        sleep(Duration::from_secs(wait)).await;
                    }
                    continue;
                }
                return Err(anyhow!("Graph UAL query start failed: {}", text));
            }
            let json = response.json::<Value>().await?;
            let query_id = json
                .get("id")
                .and_then(|id| id.as_str())
                .ok_or_else(|| anyhow!("Graph UAL query did not return an id"))?;
            debug!("Graph UAL query started successfully with id {}", query_id);
            return Ok(query_id.to_string());
        }
        Err(anyhow!(
            "Graph UAL query start failed after {} attempts due to rate limiting: {}",
            RATE_LIMIT_RETRY_ATTEMPTS,
            last_error
        ))
    }

    async fn wait_for_query_completion(&self, query_id: &str) -> Result<()> {
        let url = format!(
            "https://graph.microsoft.com/beta/security/auditLog/queries/{}",
            query_id
        );
        debug!("Polling Graph UAL query {} for completion", query_id);
        for _ in 0..POLL_ATTEMPTS {
            self.wait_for_get_rate_limit().await;
            let response = self.client
                .get(url.clone())
                .headers(self.headers.clone())
                .send()
                .await?;
            let status = response.status();
            if !status.is_success() {
                let retry_after = extract_retry_after_secs(&response);
                let text = response.text().await?;
                if is_rate_limited(status.as_u16(), &text) {
                    let wait = retry_after.unwrap_or(RATE_LIMIT_RETRY_SLEEP_SECS);
                    warn!(
                        "Graph API rate limited during query status check, waiting {} seconds",
                        wait
                    );
                    sleep(Duration::from_secs(wait)).await;
                    continue;
                }
                return Err(anyhow!("Graph UAL query status request failed: {}", text));
            }
            let json = response.json::<Value>().await?;
            let status = json
                .get("status")
                .and_then(|s| s.as_str())
                .unwrap_or("")
                .to_lowercase();
            debug!("Graph UAL query {} status: {}", query_id, status);
            if status == "succeeded" {
                info!("Graph UAL query {} completed successfully", query_id);
                return Ok(());
            }
            if status == "failed" || status == "cancelled" {
                return Err(anyhow!("Graph UAL query failed for id {}", query_id));
            }
            sleep(Duration::from_secs(POLL_INTERVAL_SECS)).await;
        }
        Err(anyhow!("Graph UAL query timed out for id {}", query_id))
    }

    async fn get_query_records(
        &self,
        query_id: &str,
        known_blobs: &HashMap<String, String>,
        skip_known_logs: bool,
    ) -> Result<Vec<GraphLogRecord>> {
        let mut next_page = Some(format!(
            "https://graph.microsoft.com/beta/security/auditLog/queries/{}/records?$top={}",
            query_id, UAL_RECORDS_PAGE_SIZE
        ));
        let mut results = Vec::new();

        while let Some(url) = next_page {
            debug!("Fetching Graph UAL records page for query {}", query_id);
            let json = self
                .get_json_with_retry(&self.fetch_client, &url, "Graph UAL records request failed")
                .await?;
            let records = json
                .get("value")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            debug!(
                "Retrieved {} Graph UAL records on this page for query {}",
                records.len(),
                query_id
            );

            for record in records {
                let map = record.as_object().cloned();
                if map.is_none() {
                    warn!("Graph UAL record was not an object, skipping.");
                    continue;
                }
                let mut log: ArbitraryJson = map.unwrap().into_iter().collect();
                normalize_creation_time(&mut log);
                if let Some(new_record) = create_graph_log_record(
                    UAL_GRAPH_CONTENT_TYPE,
                    log,
                    known_blobs,
                    skip_known_logs,
                ) {
                    results.push(new_record);
                }
            }
            next_page = json
                .get("@odata.nextLink")
                .and_then(|v| v.as_str())
                .map(|v| v.to_string());
        }
        debug!(
            "Total Graph UAL records retrieved for query {}: {}",
            query_id,
            results.len()
        );
        Ok(results)
    }

    /// Performs a GET request to `url` using the supplied `client`, retrying on rate-limit
    /// responses and on transient server errors (5xx). Returns the parsed JSON `Value` on
    /// success, or an error prefixed with `error_prefix` on failure.
    async fn get_json_with_retry(
        &self,
        client: &reqwest::Client,
        url: &str,
        error_prefix: &str,
    ) -> Result<Value> {
        debug!("Graph API GET request to: {}", url);
        let mut last_error = String::new();
        for attempt in 0..RATE_LIMIT_RETRY_ATTEMPTS {
            self.wait_for_get_rate_limit().await;
            let mut server_error_attempts = 0;
            loop {
                let response = client
                    .get(url)
                    .headers(self.headers.clone())
                    .send()
                    .await?;
                let status = response.status();
                if !status.is_success() {
                    let retry_after = extract_retry_after_secs(&response);
                    let text = response.text().await?;
                    if is_rate_limited(status.as_u16(), &text) {
                        last_error = text;
                        if attempt + 1 < RATE_LIMIT_RETRY_ATTEMPTS {
                            let wait = retry_after.unwrap_or(RATE_LIMIT_RETRY_SLEEP_SECS);
                            warn!(
                                "Graph API rate limited, waiting {} seconds before retry ({}/{})",
                                wait, attempt + 1, RATE_LIMIT_RETRY_ATTEMPTS - 1
                            );
                            sleep(Duration::from_secs(wait)).await;
                        }
                        break;
                    }
                    if is_server_error(status.as_u16())
                        && server_error_attempts < SERVER_ERROR_RETRY_ATTEMPTS
                    {
                        server_error_attempts += 1;
                        warn!(
                            "Graph API returned server error ({}), waiting {} seconds before retry ({}/{}): {}",
                            status.as_u16(),
                            SERVER_ERROR_RETRY_SLEEP_SECS,
                            server_error_attempts,
                            SERVER_ERROR_RETRY_ATTEMPTS,
                            text
                        );
                        sleep(Duration::from_secs(SERVER_ERROR_RETRY_SLEEP_SECS)).await;
                        continue;
                    }
                    return Err(anyhow!("{} (url: {}): {}", error_prefix, url, text));
                }
                return Ok(response.json::<Value>().await?);
            }
        }
        Err(anyhow!(
            "{} after {} attempts due to rate limiting: {}",
            error_prefix,
            RATE_LIMIT_RETRY_ATTEMPTS,
            last_error
        ))
    }
}

/// Extract the `Retry-After` header value (in seconds) from a response, if present.
/// Used to honour the server's requested backoff instead of a hardcoded sleep.
fn extract_retry_after_secs(response: &reqwest::Response) -> Option<u64> {
    response
        .headers()
        .get("Retry-After")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
}

fn is_rate_limited(status: u16, text: &str) -> bool {
    if status == 429 {
        return true;
    }
    let lower = text.to_lowercase();
    lower.contains("too many request") || lower.contains("please try after some time")
}

fn is_server_error(status: u16) -> bool {
    (500..600).contains(&status)
}

fn is_query_timeout_error(e: &anyhow::Error) -> bool {
    e.to_string().contains("timed out")
}

fn get_graph_record_id(log: &ArbitraryJson) -> String {
    let maybe_id = ["id", "recordId", "eventId"]
        .iter()
        .find_map(|field| log.get(*field).and_then(|v| v.as_str()));
    if let Some(id) = maybe_id {
        return id.to_string();
    }
    let fallback_time = log
        .get("createdDateTime")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    format!(
        "UALGraph-{}-{}",
        fallback_time,
        Utc::now().timestamp_nanos_opt().unwrap_or(0)
    )
}

fn create_graph_log_record(
    content_type: &str,
    log: ArbitraryJson,
    known_blobs: &HashMap<String, String>,
    skip_known_logs: bool,
) -> Option<GraphLogRecord> {
    let content_id = get_graph_record_id(&log);
    if skip_known_logs && known_blobs.contains_key(&content_id) {
        return None;
    }
    let expiration = (Utc::now() + chrono::Duration::try_days(DEFAULT_EXPIRATION_DAYS).unwrap())
        .format("%Y-%m-%dT%H:%M:%S.%fZ")
        .to_string();
    Some(GraphLogRecord {
        content_type: content_type.to_string(),
        content_id,
        expiration,
        log,
    })
}

fn normalize_creation_time(log: &mut ArbitraryJson) {
    if log.contains_key("CreationTime") {
        return;
    }
    let timestamp = ["createdDateTime", "activityDateTime", "eventDateTime"]
        .iter()
        .find_map(|field| log.get(*field).and_then(|v| v.as_str()));
    if let Some(ts) = timestamp {
        if let Ok(parsed) = DateTime::parse_from_rfc3339(ts) {
            log.insert(
                "CreationTime".to_string(),
                Value::String(
                    parsed
                        .with_timezone(&Utc)
                        .format("%Y-%m-%dT%H:%M:%S")
                        .to_string(),
                ),
            );
        }
    }
}

fn build_directory_audit_url(
    start_time: &str,
    end_time: &str,
    categories: &[String],
) -> Result<String> {
    let mut url = Url::parse("https://graph.microsoft.com/v1.0/auditLogs/directoryAudits")?;
    let filter = build_directory_audit_filter(start_time, end_time, categories);
    url.query_pairs_mut().append_pair("$filter", &filter);
    Ok(url.to_string())
}

fn build_directory_audit_filter(start_time: &str, end_time: &str, categories: &[String]) -> String {
    let mut filter = format!(
        "activityDateTime ge {} and activityDateTime le {}",
        start_time, end_time
    );
    if !categories.is_empty() {
        let category_filters = categories
            .iter()
            .map(|category| format!("category eq '{}'", category.replace('\'', "''")))
            .collect::<Vec<String>>()
            .join(" or ");
        filter = format!("{} and ({})", filter, category_filters);
    }
    filter
}

fn build_signin_url(start_time: &str, end_time: &str) -> Result<String> {
    let mut url = Url::parse("https://graph.microsoft.com/beta/auditLogs/signIns")?;
    let filter = build_signin_filter(start_time, end_time);
    url.query_pairs_mut().append_pair("$filter", &filter);
    Ok(url.to_string())
}

fn build_signin_filter(start_time: &str, end_time: &str) -> String {
    format!(
        "createdDateTime ge {} and createdDateTime le {}",
        start_time, end_time
    )
}

fn build_intune_url(start_time: &str, end_time: &str) -> Result<String> {
    let mut url =
        Url::parse("https://graph.microsoft.com/v1.0/deviceManagement/auditEvents")?;
    let filter = build_intune_filter(start_time, end_time);
    url.query_pairs_mut().append_pair("$filter", &filter);
    Ok(url.to_string())
}

fn build_intune_filter(start_time: &str, end_time: &str) -> String {
    format!(
        "activityDateTime ge {} and activityDateTime le {}",
        start_time, end_time
    )
}

#[cfg(test)]
mod tests {
    use crate::api_connection_graph::{
        build_directory_audit_filter, build_intune_filter, build_signin_filter, GraphRateLimiter,
        MAX_GET_PER_WINDOW, MAX_POST_PER_WINDOW, UAL_RECORDS_PAGE_SIZE,
    };
    use std::time::Duration;

    #[test]
    fn builds_directory_audit_filter_with_categories() {
        let filter = build_directory_audit_filter(
            "2026-01-01T00:00:00Z",
            "2026-01-01T01:00:00Z",
            &vec!["UserManagement".to_string(), "RoleManagement".to_string()],
        );
        assert_eq!(
            filter,
            "activityDateTime ge 2026-01-01T00:00:00Z and activityDateTime le 2026-01-01T01:00:00Z and (category eq 'UserManagement' or category eq 'RoleManagement')"
        );
    }

    #[test]
    fn escapes_single_quotes_in_category_filter() {
        let filter = build_directory_audit_filter(
            "2026-01-01T00:00:00Z",
            "2026-01-01T01:00:00Z",
            &vec!["Let'sTest".to_string()],
        );
        assert!(filter.contains("category eq 'Let''sTest'"));
    }

    #[test]
    fn builds_signin_filter() {
        let filter = build_signin_filter("2026-01-01T00:00:00Z", "2026-01-01T01:00:00Z");
        assert_eq!(
            filter,
            "createdDateTime ge 2026-01-01T00:00:00Z and createdDateTime le 2026-01-01T01:00:00Z"
        );
    }

    #[test]
    fn exchange_mailbox_record_type_filters_are_non_empty() {
        use crate::api_connection_graph::EXCHANGE_MAILBOX_RECORD_TYPE_FILTERS;
        assert!(
            !EXCHANGE_MAILBOX_RECORD_TYPE_FILTERS.is_empty(),
            "Exchange Mailbox record type filters should not be empty"
        );
        assert!(
            EXCHANGE_MAILBOX_RECORD_TYPE_FILTERS
                .contains(&"exchangeItem"),
            "exchangeItem should be in filters"
        );
        assert!(
            EXCHANGE_MAILBOX_RECORD_TYPE_FILTERS
                .contains(&"exchangeItemGroup"),
            "exchangeItemGroup should be in filters"
        );
        assert!(
            EXCHANGE_MAILBOX_RECORD_TYPE_FILTERS
                .contains(&"exchangeItemAggregated"),
            "exchangeItemAggregated should be in filters"
        );
    }

    #[test]
    fn builds_intune_filter() {
        let filter = build_intune_filter("2026-01-01T00:00:00Z", "2026-01-01T01:00:00Z");
        assert_eq!(
            filter,
            "activityDateTime ge 2026-01-01T00:00:00Z and activityDateTime le 2026-01-01T01:00:00Z"
        );
    }

    /// Rate limiter allows up to `MAX_POST_PER_WINDOW` POST requests in a window
    /// without any sleep, and then enforces a delay for the next request.
    #[test]
    fn rate_limiter_post_allows_up_to_limit_then_blocks() {
        let mut limiter = GraphRateLimiter::new();
        for _ in 0..MAX_POST_PER_WINDOW {
            assert_eq!(
                limiter.claim_post(),
                Duration::ZERO,
                "should not throttle within the window"
            );
        }
        let delay = limiter.claim_post();
        assert!(
            delay > Duration::ZERO,
            "should enforce a delay after exhausting the POST quota"
        );
    }

    /// Rate limiter allows up to `MAX_GET_PER_WINDOW` GET requests in a window
    /// without any sleep, and then enforces a delay for the next request.
    #[test]
    fn rate_limiter_get_allows_up_to_limit_then_blocks() {
        let mut limiter = GraphRateLimiter::new();
        for _ in 0..MAX_GET_PER_WINDOW {
            assert_eq!(
                limiter.claim_get(),
                Duration::ZERO,
                "should not throttle within the window"
            );
        }
        let delay = limiter.claim_get();
        assert!(
            delay > Duration::ZERO,
            "should enforce a delay after exhausting the GET quota"
        );
    }

    /// POST and GET quotas are tracked independently.
    #[test]
    fn rate_limiter_post_and_get_quotas_are_independent() {
        let mut limiter = GraphRateLimiter::new();
        // Exhaust the POST quota.
        for _ in 0..MAX_POST_PER_WINDOW {
            limiter.claim_post();
        }
        // GET quota should still be available.
        assert_eq!(
            limiter.claim_get(),
            Duration::ZERO,
            "GET quota must not be affected by POST exhaustion"
        );
    }

    #[test]
    fn ual_records_page_size_is_50000() {
        assert_eq!(UAL_RECORDS_PAGE_SIZE, 50000);
    }

    #[test]
    fn ual_records_url_includes_top_parameter() {
        let query_id = "test-query-id";
        let url = format!(
            "https://graph.microsoft.com/beta/security/auditLog/queries/{}/records?$top={}",
            query_id, UAL_RECORDS_PAGE_SIZE
        );
        assert!(
            url.contains("$top=50000"),
            "Records URL must include $top=50000 for batch fetching"
        );
    }
}
