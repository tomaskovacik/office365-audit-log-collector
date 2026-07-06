use std::io::{ErrorKind, Write};
use std::net::{TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};
use async_trait::async_trait;
use chrono::{DateTime, NaiveDateTime, Utc};
use log::{debug, warn};
use serde_json::{Map, Value};
use crate::config::{Config, GraylogFormat, GraylogProtocol};
use crate::data_structures::{ArbitraryJson, Caches};
use crate::interfaces::interface::Interface;

/// Maximum payload size for a single GELF UDP datagram (per the GELF specification).
const GELF_UDP_MAX_BYTES: usize = 8192;
/// Data bytes per chunk: 8192 minus the 12-byte GELF chunk header.
const GELF_CHUNK_DATA_SIZE: usize = 8180;
/// GELF spec maximum number of chunks per message.
const GELF_MAX_CHUNKS: usize = 128;
/// Magic bytes that identify a chunked GELF UDP datagram.
const GELF_CHUNKED_MAGIC: [u8; 2] = [0x1e, 0x0f];

static GELF_MSG_COUNTER: AtomicU64 = AtomicU64::new(0);

pub struct GraylogInterface {
    address: String,
    port: u16,
    format: GraylogFormat,
    host: String,
    protocol: GraylogProtocol,
    tcp_socket: Option<TcpStream>,
}

impl GraylogInterface {

    pub fn new(config: Config) -> Result<Self, std::io::Error> {

        let graylog_cfg = config.output.graylog.as_ref().unwrap();
        let address = graylog_cfg.address.clone();
        let port = graylog_cfg.port;
        let format = graylog_cfg.format.clone().unwrap_or(GraylogFormat::Raw);
        if format == GraylogFormat::Raw {
            if graylog_cfg.host.is_some() {
                return Err(std::io::Error::new(
                    ErrorKind::InvalidInput,
                    "'host' is set in the Graylog config but 'format' is 'raw' or not set — 'host' is only used with 'format: gelf'",
                ));
            }
        }
        let host = graylog_cfg.host.clone().unwrap_or_else(|| "office365-audit-collector".to_string());
        // Raw format defaults to TCP (matches the original behaviour).
        // GELF format defaults to UDP.
        let protocol = graylog_cfg.protocol.clone().unwrap_or(if format == GraylogFormat::Raw {
            GraylogProtocol::Tcp
        } else {
            GraylogProtocol::Udp
        });

        // Establish and validate the TCP connection at startup.
        // UDP is connectionless so there is nothing to test at startup.
        let tcp_socket = if protocol == GraylogProtocol::Tcp {
            Some(Self::open_tcp_socket(&address, port)?)
        } else {
            None
        };

        Ok(GraylogInterface {
            address,
            port,
            format,
            host,
            protocol,
            tcp_socket,
        })
    }
}

impl GraylogInterface {
    fn open_tcp_socket(address: &str, port: u16) -> Result<TcpStream, std::io::Error> {
        let ip_addr = (address, port)
            .to_socket_addrs()
            .map_err(|e| std::io::Error::new(e.kind(), format!("Unable to resolve the IP address: {}", e)))?
            .next()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "DNS resolution returned no IP addresses"))?;
        TcpStream::connect_timeout(&ip_addr, Duration::from_secs(10))
    }

    fn udp_send(socket: &UdpSocket, addr: &str, bytes: &[u8]) {
        if bytes.len() <= GELF_UDP_MAX_BYTES {
            socket.send_to(bytes, addr).unwrap_or_else(
                |e| { warn!("Could not send log to Graylog via UDP: {}", e); 0 });
            return;
        }

        let chunks: Vec<&[u8]> = bytes.chunks(GELF_CHUNK_DATA_SIZE).collect();
        if chunks.len() > GELF_MAX_CHUNKS {
            warn!(
                "GELF message requires {} chunks which exceeds the GELF maximum of {}, skipping.",
                chunks.len(), GELF_MAX_CHUNKS
            );
            return;
        }

        let count = GELF_MSG_COUNTER.fetch_add(1, Ordering::Relaxed);
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        let msg_id = (count ^ now).to_be_bytes();
        let chunk_count = chunks.len() as u8;

        for (i, chunk) in chunks.iter().enumerate() {
            let mut packet = Vec::with_capacity(12 + chunk.len());
            packet.extend_from_slice(&GELF_CHUNKED_MAGIC);
            packet.extend_from_slice(&msg_id);
            packet.push(i as u8);
            packet.push(chunk_count);
            packet.extend_from_slice(chunk);
            socket.send_to(&packet, addr).unwrap_or_else(
                |e| { warn!("Could not send GELF chunk {}/{} to Graylog via UDP: {}", i + 1, chunk_count, e); 0 });
        }
    }

    fn tcp_send(&mut self, framed: &[u8]) {
        // Try the existing connection; on any error drop it and reconnect once.
        let first_try = self.tcp_socket.as_mut()
            .map(|s| s.write_all(framed).and_then(|_| s.flush()));

        match first_try {
            Some(Ok(())) => return,
            Some(Err(e)) => {
                debug!("Graylog TCP write failed ({}), reconnecting.", e);
                self.tcp_socket = None;
            }
            None => {}
        }

        let address = self.address.clone();
        let port = self.port;
        match Self::open_tcp_socket(&address, port) {
            Ok(mut socket) => {
                match socket.write_all(framed).and_then(|_| socket.flush()) {
                    Ok(()) => { self.tcp_socket = Some(socket); }
                    Err(e) => warn!("Could not send log to Graylog interface: {}", e),
                }
            }
            Err(e) => warn!("Could not connect to Graylog interface on: {}:{} with: {}", address, port, e),
        }
    }
}

#[async_trait]
impl Interface for GraylogInterface {

    async fn send_logs(&mut self, mut logs: Caches) {

        let mut all_logs = logs.get_all();
        for logs in all_logs.iter_mut() {
            for log in logs.iter_mut() {

                let serialized = match self.format {
                    GraylogFormat::Raw => {
                        match add_timestamp_field(log) {
                            Ok(()) => (),
                            Err(e) => {
                                warn!("Could not parse timestamp for log in Graylog interface: {}", e);
                                continue
                            }
                        }
                        match serde_json::to_string(log) {
                            Ok(json) => json,
                            Err(e) => {
                                warn!("Could not serialize a log in Graylog interface: {}.", e);
                                continue
                            }
                        }
                    }
                    GraylogFormat::Gelf => {
                        match build_gelf_message(log, &self.host) {
                            Ok(json) => json,
                            Err(e) => {
                                warn!("Could not build GELF message in Graylog interface: {}.", e);
                                continue
                            }
                        }
                    }
                };

                let bytes = serialized.into_bytes();

                match self.protocol {
                    GraylogProtocol::Udp => {
                        match UdpSocket::bind("0.0.0.0:0") {
                            Ok(socket) => {
                                let addr = format!("{}:{}", self.address, self.port);
                                Self::udp_send(&socket, &addr, &bytes);
                            }
                            Err(e) => warn!("Could not bind UDP socket for Graylog: {}", e),
                        }
                    }
                    GraylogProtocol::Tcp => {
                        // Both Raw and GELF use the persistent connection to avoid exhausting
                        // ephemeral ports when sending large batches of logs.
                        // Raw TCP: newline-delimited JSON (configure Graylog input to split on \n).
                        // GELF TCP: null-byte framing per the GELF spec.
                        let mut framed = bytes;
                        if self.format == GraylogFormat::Gelf {
                            framed.push(0u8);
                        } else {
                            framed.push(b'\n');
                        }
                        self.tcp_send(&framed);
                    }
                }
            }
        }
    }
}


pub fn add_timestamp_field(log: &mut ArbitraryJson) -> Result<(), std::io::Error> {

    let time_value = if let Some(i) = log.get("CreationTime") {
        i
    } else {
        return Err(std::io::Error::new(
            ErrorKind::NotFound, "Expected CreationTime field".to_string()))
    };

    let time_string = if let Some(i) = time_value.as_str() {
        i
    } else {
        return Err(std::io::Error::new(
            ErrorKind::NotFound, "Could not convert timestamp field to string".to_string()))

    };

    let time = if let Ok(i) =
            NaiveDateTime::parse_from_str(time_string, "%Y-%m-%dT%H:%M:%S") {
        i
    } else {
        return Err(std::io::Error::new(
            ErrorKind::NotFound, "Could parse time of log".to_string()))
    };

    let time_utc = DateTime::<Utc>::from_naive_utc_and_offset(time, Utc);
    let mut time_stamp = time_utc.format("%Y-%m-%d %H:%M:%S.%f").to_string();
    time_stamp = time_stamp[..time_stamp.len() - 6].to_string();
    log.insert("timestamp".to_string(), Value::String(time_stamp));
    Ok(())
}

/// Recursively flatten a single JSON value into GELF additional fields under `prefix`.
///
/// Dispatch rules (applied at every nesting level):
/// - `Null`   → omit entirely.
/// - `Object` → iterate keys, skip `@`-prefixed OData annotations, recurse for each entry.
/// - `Array`  → iterate elements with a 0-based index suffix, recurse for each element.
/// - `String` → if the content parses as a JSON object or array, recurse into it;
///              otherwise keep as-is.
/// - `Number` → insert directly (kept as a JSON number, not coerced to a string).
/// - `Bool`   → coerce to its JSON string representation.
fn flatten_value_into_gelf(value: &Value, prefix: &str, gelf: &mut Map<String, Value>) {
    match value {
        Value::Null => {}
        Value::Object(map) => {
            flatten_object_into_gelf(map, prefix, gelf);
        }
        Value::Array(items) => {
            // Office 365 uses {"Name": ..., "Value": ...} arrays for ExtendedProperties,
            // Parameters, and ModifiedProperties.  Flatten these as named fields so that
            // e.g. ApplicationDisplayName is searchable directly rather than being buried
            // under a numeric index suffix.  ModifiedProperties also carries OldValue/NewValue.
            let is_named_kv = !items.is_empty() && items.iter().all(|item| {
                matches!(item, Value::Object(m) if m.contains_key("Name"))
            });
            if is_named_kv {
                for item in items {
                    if let Value::Object(m) = item {
                        let name = m.get("Name").and_then(|v| v.as_str()).unwrap_or("");
                        if name.is_empty() {
                            continue;
                        }
                        // Promote directly as a top-level GELF field, dropping the container
                        // prefix (e.g. _ExtendedProperties_ApplicationDisplayName →
                        // _ApplicationDisplayName). Collisions are extremely unlikely in O365
                        // audit logs.
                        if let Some(v) = m.get("Value") {
                            flatten_value_into_gelf(v, &format!("_{}", name), gelf);
                        }
                        if let Some(v) = m.get("OldValue") {
                            flatten_value_into_gelf(v, &format!("_{}_OldValue", name), gelf);
                        }
                        if let Some(v) = m.get("NewValue") {
                            flatten_value_into_gelf(v, &format!("_{}_NewValue", name), gelf);
                        }
                    }
                }
            } else {
                for (i, item) in items.iter().enumerate() {
                    let field_name = format!("{}_{}", prefix, i);
                    flatten_value_into_gelf(item, &field_name, gelf);
                }
            }
        }
        Value::String(s) => {
            let trimmed = s.trim_start();
            // If the string is itself a JSON object or array, parse and recurse so that
            // fields serialised as escaped JSON (e.g. AppAccessContext, Folders) become
            // individual searchable GELF fields.
            if trimmed.starts_with('{') || trimmed.starts_with('[') {
                if let Ok(parsed) = serde_json::from_str::<Value>(s) {
                    match &parsed {
                        Value::Object(_) | Value::Array(_) => {
                            flatten_value_into_gelf(&parsed, prefix, gelf);
                            return;
                        }
                        _ => {}
                    }
                }
            }
            gelf.insert(prefix.to_string(), value.clone());
        }
        Value::Number(_) => {
            gelf.insert(prefix.to_string(), value.clone());
        }
        other => {
            gelf.insert(prefix.to_string(), Value::String(other.to_string()));
        }
    }
}

/// Recursively flatten a JSON object into GELF additional fields.
///
/// Each key in `map` is appended to `prefix` (separated by `_`) to form the GELF field name,
/// then delegated to `flatten_value_into_gelf` for further recursion.
/// `@`-prefixed OData annotation keys are skipped at every level.
fn flatten_object_into_gelf(map: &Map<String, Value>, prefix: &str, gelf: &mut Map<String, Value>) {
    for (key, value) in map {
        // Skip OData type annotations – they are meta-data noise.
        if key.starts_with('@') {
            continue;
        }
        let field_name = format!("{}_{}", prefix, key);
        flatten_value_into_gelf(value, &field_name, gelf);
    }
}

/// Build a GELF 1.1 message from an audit log entry.
///
/// Required GELF fields:
/// - `version`: always `"1.1"`
/// - `host`: identifies the sender (configurable, defaults to `"office365-audit-collector"`)
/// - `short_message`: a short human-readable summary; we use the `Operation` field when present
/// - `timestamp`: Unix epoch as a floating-point number derived from `CreationTime`
///
/// All other audit log fields are included as GELF additional fields, prefixed with `_`.
/// When received by a `GELF UDP` or `GELF TCP` Graylog input these become first-class message fields,
/// removing the need for a JSON extractor.
pub fn build_gelf_message(log: &ArbitraryJson, host: &str) -> Result<String, std::io::Error> {

    let creation_time = log.get("CreationTime")
        .and_then(|v| v.as_str())
        .ok_or_else(|| std::io::Error::new(ErrorKind::NotFound, "Expected CreationTime field"))?;

    let naive = NaiveDateTime::parse_from_str(creation_time, "%Y-%m-%dT%H:%M:%S")
        .map_err(|_| std::io::Error::new(ErrorKind::InvalidData, "Could not parse CreationTime"))?;
    let timestamp_secs = DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc).timestamp() as f64;

    // Graph API UAL records use camelCase "operation"; Management API records use "Operation".
    // Check both so that all log sources get a meaningful short_message.
    let short_message = log.get("Operation")
        .or_else(|| log.get("operation"))
        .and_then(|v| v.as_str())
        .unwrap_or("Office365AuditLog")
        .to_string();

    let mut gelf: Map<String, Value> = Map::new();
    gelf.insert("version".to_string(), Value::String("1.1".to_string()));
    gelf.insert("host".to_string(), Value::String(host.to_string()));
    gelf.insert("short_message".to_string(), Value::String(short_message));
    gelf.insert("timestamp".to_string(), Value::Number(
        serde_json::Number::from_f64(timestamp_secs)
            .ok_or_else(|| std::io::Error::new(ErrorKind::InvalidData, "Could not encode timestamp as JSON number"))?
    ));

    for (key, value) in log {
        // The GELF spec reserves `_id`; skip it to avoid conflicts with Graylog's internal id.
        if key == "id" {
            continue;
        }
        // UALGraph records carry a nested `auditData` JSON object that contains the most
        // useful audit fields (ClientIP, Operation, UserId, ObjectId, …).  Serialising the
        // whole object as a single escaped JSON string makes those fields un-searchable in
        // Graylog.  Recursively flatten the object into individual `_auditData_<field>`
        // GELF fields so that even deeply-nested sub-objects (e.g. AppAccessContext) become
        // individual searchable fields.
        if key == "auditData" {
            if let Value::Object(map) = value {
                flatten_object_into_gelf(map, "_auditData", &mut gelf);
            }
            continue;
        }
        // Recursively flatten all remaining fields.  This handles Office Management API
        // records whose top-level values may be nested objects, arrays of objects (e.g.
        // `Parameters`, `ExtendedProperties`, `Actor`, `Folders`), strings that embed JSON
        // objects/arrays, booleans, numbers, and nulls.  Null values are omitted; booleans
        // are coerced to their string representation; scalars are kept as-is; objects and
        // arrays are expanded with `_` / 0-based-index suffixes recursively so every leaf
        // value becomes its own searchable GELF field.
        let gelf_key = format!("_{}", key);
        flatten_value_into_gelf(value, &gelf_key, &mut gelf);
    }

    serde_json::to_string(&gelf)
        .map_err(|e| std::io::Error::new(ErrorKind::Other, format!("Could not serialize GELF message: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn make_log(operation: &str, creation_time: &str) -> ArbitraryJson {
        let mut log = ArbitraryJson::new();
        log.insert("Operation".to_string(), Value::String(operation.to_string()));
        log.insert("CreationTime".to_string(), Value::String(creation_time.to_string()));
        log.insert("UserId".to_string(), Value::String("user@example.com".to_string()));
        log
    }

    #[test]
    fn gelf_message_has_required_fields() {
        let log = make_log("AzureActiveDirectoryAccountLogon", "2024-04-24T10:00:00");
        let json_str = build_gelf_message(&log, "office365-audit-collector").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        assert_eq!(parsed["version"], "1.1");
        assert_eq!(parsed["host"], "office365-audit-collector");
        assert_eq!(parsed["short_message"], "AzureActiveDirectoryAccountLogon");
        assert!(parsed["timestamp"].is_number());
    }

    #[test]
    fn gelf_message_prefixes_additional_fields() {
        let log = make_log("FileAccessed", "2024-04-24T10:00:00");
        let json_str = build_gelf_message(&log, "myhost").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        assert_eq!(parsed["_UserId"], "user@example.com");
        assert_eq!(parsed["_Operation"], "FileAccessed");
        assert_eq!(parsed["_CreationTime"], "2024-04-24T10:00:00");
    }

    #[test]
    fn gelf_message_falls_back_to_short_message_when_no_operation() {
        let mut log = ArbitraryJson::new();
        log.insert("CreationTime".to_string(), Value::String("2024-04-24T10:00:00".to_string()));
        let json_str = build_gelf_message(&log, "myhost").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed["short_message"], "Office365AuditLog");
    }

    #[test]
    fn gelf_message_errors_without_creation_time() {
        let mut log = ArbitraryJson::new();
        log.insert("Operation".to_string(), Value::String("Test".to_string()));
        assert!(build_gelf_message(&log, "myhost").is_err());
    }

    #[test]
    fn gelf_message_flattens_top_level_array() {
        let mut log = make_log("FileAccessed", "2024-04-24T10:00:00");
        log.insert("Parameters".to_string(), serde_json::json!([{"Name": "foo", "Value": "bar"}]));
        let json_str = build_gelf_message(&log, "myhost").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        // Named KV arrays are promoted directly — container prefix is dropped.
        assert!(parsed.get("_Parameters").is_none(), "_Parameters must be flattened");
        assert!(parsed.get("_Parameters_0_Name").is_none(), "indexed form must not appear");
        assert_eq!(parsed["_foo"], "bar");
    }

    #[test]
    fn gelf_message_flattens_top_level_object() {
        let mut log = make_log("FileAccessed", "2024-04-24T10:00:00");
        log.insert("Nested".to_string(), serde_json::json!({"key": "value"}));
        let json_str = build_gelf_message(&log, "myhost").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        // Raw object must not appear; its fields must be promoted
        assert!(parsed.get("_Nested").is_none(), "_Nested must be flattened, not stored as a string");
        assert_eq!(parsed["_Nested_key"], "value");
    }

    #[test]
    fn gelf_message_coerces_bool_value_to_string() {
        let mut log = make_log("FileAccessed", "2024-04-24T10:00:00");
        log.insert("IsAnonymous".to_string(), Value::Bool(true));
        let json_str = build_gelf_message(&log, "myhost").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert!(parsed["_IsAnonymous"].is_string(), "_IsAnonymous must be coerced to a string");
        assert_eq!(parsed["_IsAnonymous"], "true");
    }

    #[test]
    fn gelf_message_preserves_string_and_number_values() {
        let mut log = make_log("FileAccessed", "2024-04-24T10:00:00");
        log.insert("RecordType".to_string(), Value::Number(serde_json::Number::from(14)));
        let json_str = build_gelf_message(&log, "myhost").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert!(parsed["_RecordType"].is_number(), "_RecordType must remain a number");
        assert_eq!(parsed["_UserId"], "user@example.com");
    }


    #[test]
    fn gelf_message_excludes_id_field() {
        let mut log = make_log("FileAccessed", "2024-04-24T10:00:00");
        log.insert("id".to_string(), Value::String("some-id".to_string()));
        let json_str = build_gelf_message(&log, "myhost").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert!(parsed.get("_id").is_none(), "_id must not appear in GELF message");
    }

    #[test]
    fn gelf_message_omits_null_field() {
        let mut log = make_log("FileAccessed", "2024-04-24T10:00:00");
        log.insert("clientIp".to_string(), Value::Null);
        let json_str = build_gelf_message(&log, "myhost").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert!(parsed.get("_clientIp").is_none(), "_clientIp must be omitted when null, not serialized as \"null\"");
    }

    #[test]
    fn gelf_message_uses_lowercase_operation_for_short_message() {
        let mut log = ArbitraryJson::new();
        log.insert("CreationTime".to_string(), Value::String("2024-04-24T10:00:00".to_string()));
        // Graph API UAL records use camelCase "operation" instead of "Operation"
        log.insert("operation".to_string(), Value::String("PreAuthTokenUsedExtended".to_string()));
        let json_str = build_gelf_message(&log, "myhost").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed["short_message"], "PreAuthTokenUsedExtended",
            "short_message must use camelCase 'operation' field when PascalCase 'Operation' is absent");
    }

    #[test]
    fn gelf_message_prefers_pascalcase_operation_over_lowercase() {
        let mut log = ArbitraryJson::new();
        log.insert("CreationTime".to_string(), Value::String("2024-04-24T10:00:00".to_string()));
        log.insert("Operation".to_string(), Value::String("FileAccessed".to_string()));
        log.insert("operation".to_string(), Value::String("OtherOperation".to_string()));
        let json_str = build_gelf_message(&log, "myhost").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed["short_message"], "FileAccessed",
            "PascalCase 'Operation' must take precedence over camelCase 'operation'");
    }

    #[test]
    fn gelf_message_flattens_audit_data_object() {
        let mut log = make_log("FileAccessedExtended", "2024-04-24T10:00:00");
        log.insert("auditData".to_string(), serde_json::json!({
            "@odata.type": "#microsoft.graph.security.defaultAuditData",
            "ClientIP": "4.210.128.168",
            "Operation": "FileAccessedExtended",
            "RecordType": 6,
            "AppAccessContext": {"AADSessionId": "abc", "ClientAppName": "App Service"},
            "NullField": null
        }));
        let json_str = build_gelf_message(&log, "myhost").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        // The raw _auditData blob must NOT appear
        assert!(parsed.get("_auditData").is_none(), "_auditData must be flattened, not serialized as a string");
        // Scalar fields are promoted to top-level GELF fields
        assert_eq!(parsed["_auditData_ClientIP"], "4.210.128.168", "_auditData_ClientIP must be a string");
        assert_eq!(parsed["_auditData_Operation"], "FileAccessedExtended", "_auditData_Operation must be a string");
        assert!(parsed["_auditData_RecordType"].is_number(), "_auditData_RecordType must be a number");
        // Nested objects are recursively flattened
        assert_eq!(parsed["_auditData_AppAccessContext_AADSessionId"], "abc",
            "_auditData_AppAccessContext_AADSessionId must be flattened from the nested object");
        assert_eq!(parsed["_auditData_AppAccessContext_ClientAppName"], "App Service",
            "_auditData_AppAccessContext_ClientAppName must be flattened from the nested object");
        assert!(parsed.get("_auditData_AppAccessContext").is_none(),
            "_auditData_AppAccessContext must not appear as a raw string after flattening");
        // odata type annotations are dropped
        assert!(parsed.get("_auditData_@odata.type").is_none(), "odata type annotations must be omitted");
        // Null sub-fields are omitted
        assert!(parsed.get("_auditData_NullField").is_none(), "null auditData fields must be omitted");
    }

    #[test]
    fn gelf_message_flattens_audit_data_string_encoded_nested_object() {
        // Some Graph API responses serialise sub-objects as escaped JSON strings.
        // The real-world example is AppAccessContext arriving as a JSON string rather than
        // a native JSON object.  The flattener must detect this and recurse into it.
        let mut log = make_log("FileAccessedExtended", "2024-04-24T10:00:00");
        log.insert("auditData".to_string(), serde_json::json!({
            "ClientIP": "4.210.128.168",
            "AppAccessContext": "{\"@odata.type\":\"#microsoft.graph.security.defaultAuditData\",\"AADSessionId\":\"004db2b9-de97-c009-44f9-214e4f43b48d\",\"ClientAppId\":\"b15665d9-eda6-4092-8539-0eec376afd59\",\"ClientAppName\":\"rclone\"}"
        }));
        let json_str = build_gelf_message(&log, "myhost").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        // The string-encoded object must be parsed and its fields promoted
        assert_eq!(parsed["_auditData_AppAccessContext_AADSessionId"], "004db2b9-de97-c009-44f9-214e4f43b48d");
        assert_eq!(parsed["_auditData_AppAccessContext_ClientAppName"], "rclone");
        // OData annotation inside the string-encoded object must also be dropped
        assert!(parsed.get("_auditData_AppAccessContext_@odata.type").is_none(),
            "odata annotations inside string-encoded nested objects must be omitted");
        // The raw string field must not appear
        assert!(parsed.get("_auditData_AppAccessContext").is_none(),
            "_auditData_AppAccessContext must not appear as a raw string");
    }

    #[test]
    fn add_timestamp_field_adds_timestamp() {
        let mut log = ArbitraryJson::new();
        log.insert("CreationTime".to_string(), Value::String("2024-04-24T10:00:00".to_string()));
        add_timestamp_field(&mut log).unwrap();
        assert!(log.contains_key("timestamp"));
    }

    #[test]
    fn gelf_message_flattens_audit_data_array() {
        // auditData may contain array-valued fields whose elements are objects.
        // Each element must be expanded with a 0-based index suffix.
        let mut log = make_log("FolderBind", "2026-04-25T05:33:44");
        log.insert("auditData".to_string(), serde_json::json!({
            "ClientIP": "1.2.3.4",
            "Folders": [
                {
                    "Id": "folder-001",
                    "FolderItems": [
                        {"CreationTime": "2026-04-25T05:33:44Z", "Id": "item-001"},
                        {"CreationTime": "2026-04-25T05:33:45Z", "Id": "item-002"}
                    ]
                },
                {
                    "Id": "folder-002",
                    "FolderItems": []
                }
            ]
        }));
        let json_str = build_gelf_message(&log, "myhost").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        // Raw array field must not appear
        assert!(parsed.get("_auditData_Folders").is_none(),
            "_auditData_Folders must be flattened, not stored as an array string");
        // First folder scalar
        assert_eq!(parsed["_auditData_Folders_0_Id"], "folder-001");
        // Nested array inside first folder
        assert_eq!(parsed["_auditData_Folders_0_FolderItems_0_Id"], "item-001");
        assert_eq!(parsed["_auditData_Folders_0_FolderItems_0_CreationTime"], "2026-04-25T05:33:44Z");
        assert_eq!(parsed["_auditData_Folders_0_FolderItems_1_Id"], "item-002");
        // Second folder scalar
        assert_eq!(parsed["_auditData_Folders_1_Id"], "folder-002");
    }

    #[test]
    fn gelf_message_flattens_audit_data_string_encoded_array() {
        // Some Graph API responses serialise array-valued sub-fields as escaped JSON strings.
        // The flattener must detect the leading '[' and expand them.
        let mut log = make_log("FolderBind", "2026-04-25T05:33:44");
        log.insert("auditData".to_string(), serde_json::json!({
            "ClientIP": "1.2.3.4",
            "Folders": "[{\"Id\":\"folder-str-001\",\"FolderItems\":[{\"Id\":\"item-str-001\"}]}]"
        }));
        let json_str = build_gelf_message(&log, "myhost").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        // Raw string field must not appear
        assert!(parsed.get("_auditData_Folders").is_none(),
            "_auditData_Folders must not appear as a raw string");
        assert_eq!(parsed["_auditData_Folders_0_Id"], "folder-str-001");
        assert_eq!(parsed["_auditData_Folders_0_FolderItems_0_Id"], "item-str-001");
    }

    #[test]
    fn udp_send_chunks_oversized_message() {
        use std::net::UdpSocket;
        // Build a payload larger than 8192 bytes.
        let payload = vec![b'x'; GELF_UDP_MAX_BYTES + 1];
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = format!("127.0.0.1:{}", server.local_addr().unwrap().port());
        let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
        server.set_nonblocking(true).unwrap();

        GraylogInterface::udp_send(&socket, &addr, &payload);

        // We expect two chunks (8180 + remaining bytes), each with the 12-byte header.
        let mut buf = [0u8; 9000];
        let n1 = server.recv(&mut buf).unwrap();
        let n2 = server.recv(&mut buf).unwrap();
        assert!(n1 > 12 && n2 > 12, "each chunk must have a header and data");
        assert_eq!(&buf[..2], &GELF_CHUNKED_MAGIC, "first chunk must start with magic bytes");
        // Total data across both chunks must equal the original payload length.
        assert_eq!((n1 - 12) + (n2 - 12), payload.len());
    }
}

