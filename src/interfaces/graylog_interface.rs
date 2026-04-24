use std::io::{ErrorKind, Write};
use std::net::{TcpStream, ToSocketAddrs, UdpSocket};
use std::time::Duration;
use async_trait::async_trait;
use chrono::{DateTime, NaiveDateTime, Utc};
use log::{debug, warn};
use serde_json::{Map, Value};
use crate::config::{Config, GraylogFormat, GraylogProtocol};
use crate::data_structures::{ArbitraryJson, Caches};
use crate::interfaces::interface::Interface;

/// Maximum payload size for a single GELF UDP datagram (per the GELF specification).
const GELF_UDP_MAX_BYTES: usize = 8192;

pub struct GraylogInterface {
    address: String,
    port: u16,
    format: GraylogFormat,
    host: String,
    protocol: GraylogProtocol,
}

impl GraylogInterface {

    pub fn new(config: Config) -> Result<Self, std::io::Error> {

        let graylog_cfg = config.output.graylog.as_ref().unwrap();
        let address = graylog_cfg.address.clone();
        let port = graylog_cfg.port;
        let format = graylog_cfg.format.clone().unwrap_or(GraylogFormat::Raw);
        let host = graylog_cfg.host.clone().unwrap_or_else(|| "office365-audit-collector".to_string());
        let protocol = graylog_cfg.protocol.clone().unwrap_or(GraylogProtocol::Tcp);
        let interface = GraylogInterface {
            address,
            port,
            format,
            host,
            protocol,
        };

        // Test TCP connection at startup to catch misconfigured address/port early.
        // UDP is connectionless so there is nothing to test at startup.
        if interface.protocol == GraylogProtocol::Tcp {
            interface.get_tcp_socket()?;
        }
        Ok(interface)
    }
}

impl GraylogInterface {
    fn get_tcp_socket(&self) -> Result<TcpStream, std::io::Error> {

        let ip_addr = (self.address.clone(), self.port)
            .to_socket_addrs()
            .map_err(|e| std::io::Error::new(e.kind(), format!("Unable to resolve the IP address: {}", e)))?
            .next()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "DNS resolution returned no IP addresses"))?;
        TcpStream::connect_timeout(&ip_addr, Duration::from_secs(10))
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

                // Print the serialized message to stdout so it can be inspected when debugging
                // connectivity issues.
                let printable = std::str::from_utf8(&bytes).unwrap_or("<non-utf8>");
                println!("[graylog-debug] sending to {}:{} ({}): {}", self.address, self.port,
                    if self.protocol == GraylogProtocol::Udp { "udp" } else { "tcp" }, printable);
                debug!("[graylog-debug] sending to {}:{} ({}): {}", self.address, self.port,
                    if self.protocol == GraylogProtocol::Udp { "udp" } else { "tcp" }, printable);

                match self.protocol {
                    GraylogProtocol::Udp => {
                        // GELF over UDP: the payload is the raw GELF message with no framing.
                        // The GELF specification limits a single UDP datagram to 8192 bytes.
                        // Larger payloads would require GELF chunking which is not implemented;
                        // warn and skip rather than send a truncated or malformed message.
                        if bytes.len() > GELF_UDP_MAX_BYTES {
                            warn!(
                                "GELF message is {} bytes which exceeds the UDP maximum of {} bytes, skipping.",
                                bytes.len(), GELF_UDP_MAX_BYTES
                            );
                            continue;
                        }
                        match UdpSocket::bind("0.0.0.0:0") {
                            Ok(socket) => {
                                let addr = format!("{}:{}", self.address, self.port);
                                socket.send_to(&bytes, &addr).unwrap_or_else(
                                    |e| { warn!("Could not send log to Graylog via UDP: {}", e); 0 });
                            }
                            Err(e) => warn!("Could not bind UDP socket for Graylog: {}", e),
                        }
                    }
                    GraylogProtocol::Tcp => {
                        // GELF TCP framing: each message is terminated with a null byte.
                        // Raw mode must NOT include the null byte so that Graylog's Raw/Plaintext
                        // TCP input can parse the JSON without a trailing null corrupting it.
                        let mut framed = bytes;
                        if self.format == GraylogFormat::Gelf {
                            framed.push(0u8);
                        }
                        match self.get_tcp_socket() {
                            Ok(mut socket) => {
                                socket.write_all(&framed).unwrap_or_else(
                                    |e| warn!("Could not send log to Graylog interface: {}", e));
                                socket.flush().unwrap_or_else(
                                    |e| warn!("Could not send log to Graylog interface: {}", e));
                            }
                            Err(e) => warn!("Could not connect to Graylog interface on: {}:{} with: {}", self.address, self.port, e),
                        }
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

/// Build a GELF 1.1 message from an audit log entry.
///
/// Required GELF fields:
/// - `version`: always `"1.1"`
/// - `host`: identifies the sender (configurable, defaults to `"office365-audit-collector"`)
/// - `short_message`: a short human-readable summary; we use the `Operation` field when present
/// - `timestamp`: Unix epoch as a floating-point number derived from `CreationTime`
///
/// All other audit log fields are included as GELF additional fields, prefixed with `_`.
/// When received by a `GELF TCP` Graylog input these become first-class message fields,
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
        // Graylog.  Flatten one level of the object into individual `_auditData_<field>`
        // GELF fields instead.
        if key == "auditData" {
            if let Value::Object(map) = value {
                for (nested_key, nested_value) in map {
                    // Skip odata type annotations – they are meta-data noise.
                    if nested_key.starts_with('@') {
                        continue;
                    }
                    let gelf_nested_value = match nested_value {
                        Value::Null => continue,
                        Value::String(_) | Value::Number(_) => nested_value.clone(),
                        other => Value::String(other.to_string()),
                    };
                    gelf.insert(format!("_auditData_{}", nested_key), gelf_nested_value);
                }
            }
            continue;
        }
        // GELF additional fields must be strings or numbers.  Arrays, objects, booleans, and
        // nulls are not permitted.  Null fields are omitted entirely to avoid inserting a
        // meaningless string "null" into Graylog (e.g. Graph API records often send clientIp as
        // null when no IP is present).  Other non-scalar values are coerced to their JSON string
        // representation so that Graylog does not silently drop the entire message.  Office 365
        // audit logs commonly contain array-valued fields such as `Parameters`,
        // `ExtendedProperties`, and `Actor`.
        let gelf_value = match value {
            Value::Null => continue,
            Value::String(_) | Value::Number(_) => value.clone(),
            other => Value::String(other.to_string()),
        };
        let gelf_key = format!("_{}", key);
        gelf.insert(gelf_key, gelf_value);
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
    fn gelf_message_coerces_array_value_to_string() {
        let mut log = make_log("FileAccessed", "2024-04-24T10:00:00");
        log.insert("Parameters".to_string(), serde_json::json!([{"Name": "foo", "Value": "bar"}]));
        let json_str = build_gelf_message(&log, "myhost").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        // Must be a string, not an array
        assert!(parsed["_Parameters"].is_string(), "_Parameters must be coerced to a string");
    }

    #[test]
    fn gelf_message_coerces_object_value_to_string() {
        let mut log = make_log("FileAccessed", "2024-04-24T10:00:00");
        log.insert("Nested".to_string(), serde_json::json!({"key": "value"}));
        let json_str = build_gelf_message(&log, "myhost").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert!(parsed["_Nested"].is_string(), "_Nested must be coerced to a string");
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
        // Nested objects are coerced to a string
        assert!(parsed["_auditData_AppAccessContext"].is_string(), "_auditData_AppAccessContext must be coerced to a string");
        // odata type annotations are dropped
        assert!(parsed.get("_auditData_@odata.type").is_none(), "odata type annotations must be omitted");
        // Null sub-fields are omitted
        assert!(parsed.get("_auditData_NullField").is_none(), "null auditData fields must be omitted");
    }

    #[test]
    fn add_timestamp_field_adds_timestamp() {
        let mut log = ArbitraryJson::new();
        log.insert("CreationTime".to_string(), Value::String("2024-04-24T10:00:00".to_string()));
        add_timestamp_field(&mut log).unwrap();
        assert!(log.contains_key("timestamp"));
    }
}

