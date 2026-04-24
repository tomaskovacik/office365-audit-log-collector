use std::io::{ErrorKind, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;
use async_trait::async_trait;
use chrono::{DateTime, NaiveDateTime, Utc};
use log::warn;
use serde_json::{Map, Value};
use crate::config::{Config, GraylogFormat};
use crate::data_structures::{ArbitraryJson, Caches};
use crate::interfaces::interface::Interface;

pub struct GraylogInterface {
    address: String,
    port: u16,
    format: GraylogFormat,
    host: String,
}

impl GraylogInterface {

    pub fn new(config: Config) -> Result<Self, std::io::Error> {

        let graylog_cfg = config.output.graylog.as_ref().unwrap();
        let address = graylog_cfg.address.clone();
        let port = graylog_cfg.port;
        let format = graylog_cfg.format.clone().unwrap_or(GraylogFormat::Raw);
        let host = graylog_cfg.host.clone().unwrap_or_else(|| "office365-audit-collector".to_string());
        let interface = GraylogInterface {
            address,
            port,
            format,
            host,
        };

        // Test socket connection at startup
        interface.get_socket()?;
        Ok(interface)
    }
}

impl GraylogInterface {
    fn get_socket(&self) -> Result<TcpStream, std::io::Error> {

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

                let mut bytes = serialized.into_bytes();
                // GELF TCP framing requires a null byte terminator; also append it for raw mode
                // so the framing is consistent (Graylog raw input ignores trailing null bytes).
                bytes.push(0u8);

                match self.get_socket() {
                    Ok(mut socket) => {
                        socket.write_all(&bytes).unwrap_or_else(
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

    let short_message = log.get("Operation")
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
        // All other audit log fields are included as GELF additional fields (prefixed with `_`).
        // This means fields like `Operation` and `CreationTime` appear as both the GELF required
        // fields (`short_message`/`timestamp`) and as searchable additional fields (`_Operation`/
        // `_CreationTime`), which is intentional and standard GELF practice.
        if key == "id" {
            continue;
        }
        let gelf_key = format!("_{}", key);
        gelf.insert(gelf_key, value.clone());
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
    fn gelf_message_excludes_id_field() {
        let mut log = make_log("FileAccessed", "2024-04-24T10:00:00");
        log.insert("id".to_string(), Value::String("some-id".to_string()));
        let json_str = build_gelf_message(&log, "myhost").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert!(parsed.get("_id").is_none(), "_id must not appear in GELF message");
    }

    #[test]
    fn add_timestamp_field_adds_timestamp() {
        let mut log = ArbitraryJson::new();
        log.insert("CreationTime".to_string(), Value::String("2024-04-24T10:00:00".to_string()));
        add_timestamp_field(&mut log).unwrap();
        assert!(log.contains_key("timestamp"));
    }
}

