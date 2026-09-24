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

/// Arrays split into one message per element when the config does not say otherwise.
/// `Folders` is last so that a `MailItemsAccessed` Bind record splits per mail item, and a
/// Sync record -- which carries no `FolderItems` -- falls through to one message per folder.
const DEFAULT_SPLIT_ARRAYS: [&str; 4] =
    ["FolderItems", "AffectedItems", "MessageItems", "Folders"];

/// Fields coerced to text because Office 365 sends them with an inconsistent type.
/// `ListBaseType` is `1` on a `FileAccessed` record and `"DocumentLibrary"` on a
/// `ListViewed` one; a scan of 2422 live records found no other field that varies.
const DEFAULT_STRING_FIELDS: [&str; 1] = ["ListBaseType"];

pub struct GraylogInterface {
    address: String,
    port: u16,
    format: GraylogFormat,
    host: String,
    protocol: GraylogProtocol,
    split_arrays: Vec<String>,
    string_fields: Vec<String>,
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

        let split_arrays = graylog_cfg.split_arrays.clone().unwrap_or_else(|| {
            DEFAULT_SPLIT_ARRAYS.iter().map(|s| s.to_string()).collect()
        });

        let string_fields = graylog_cfg.string_fields.clone().unwrap_or_else(|| {
            DEFAULT_STRING_FIELDS.iter().map(|s| s.to_string()).collect()
        });

        Ok(GraylogInterface {
            address,
            port,
            format,
            host,
            protocol,
            split_arrays,
            string_fields,
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

                let serialized: Vec<String> = match self.format {
                    GraylogFormat::Raw => {
                        match add_timestamp_field(log) {
                            Ok(()) => (),
                            Err(e) => {
                                warn!("Could not parse timestamp for log in Graylog interface: {}", e);
                                continue
                            }
                        }
                        match serde_json::to_string(log) {
                            Ok(json) => vec![json],
                            Err(e) => {
                                warn!("Could not serialize a log in Graylog interface: {}.", e);
                                continue
                            }
                        }
                    }
                    GraylogFormat::Gelf => {
                        match build_gelf_messages(log, &self.host, &self.split_arrays, &self.string_fields) {
                            Ok(msgs) => msgs,
                            Err(e) => {
                                warn!("Could not build GELF message in Graylog interface: {}.", e);
                                continue
                            }
                        }
                    }
                };

                for serialized in serialized {
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

/// Separators used when several array elements collapse onto one field name.  Nesting depth
/// picks the separator so that an outer element boundary stays distinguishable from a value
/// boundary inside it: `"a, b; c, d"` is two elements of two values, not four of one.
const SEPARATOR_OUTER: &str = "; ";
const SEPARATOR_INNER: &str = ", ";

fn separator_for_depth(array_depth: usize) -> &'static str {
    if array_depth <= 1 { SEPARATOR_OUTER } else { SEPARATOR_INNER }
}

/// Recursively flatten a single JSON value into GELF additional fields under `prefix`.
///
/// Dispatch rules (applied at every nesting level):
/// - `Null`   → omit entirely.
/// - `Object` → iterate keys, skip OData annotations, recurse for each entry.
/// - `Array`  → every element writes to the *same* field name (see below), and a
///              `<prefix>_json` companion preserves the original structure.
/// - `String` → if the content parses as a JSON object or array, recurse into it;
///              otherwise keep as-is.
/// - `Number` → insert directly, unless array-derived (see `in_array`).
/// - `Bool`   → coerce to its JSON string representation.
///
/// `in_array` marks values that came from inside an array. Those are always written as
/// strings, even when a single element makes them look scalar: Graylog serialises a
/// multi-valued field to text, so a field that is a number for a one-element array and
/// text for a two-element one would flip type between documents and OpenSearch would
/// reject the second with a mapping conflict.
fn flatten_value_into_gelf(
    value: &Value,
    prefix: &str,
    gelf: &mut Map<String, Value>,
    array_depth: usize,
) {
    match value {
        Value::Null => {}
        Value::Object(map) => {
            flatten_object_into_gelf(map, prefix, gelf, array_depth);
        }
        Value::Array(items) => {
            // Office 365 uses {"Name": ..., "Value": ...} entries for ExtendedProperties,
            // Parameters, and ModifiedProperties.  Promote those as named fields so that
            // e.g. ApplicationDisplayName is searchable directly rather than being buried
            // under a numeric index suffix.  ModifiedProperties also carries OldValue/NewValue.
            //
            // The decision is made per entry, not per array: a single entry that does not
            // follow the convention used to demote the whole array to positional field names
            // (_ExtendedProperties_0_Name = "ApplicationDisplayName"), which turns the field
            // name into a *value* and hides it from aggregations.
            let mut any_collapsed = false;
            for item in items {
                // Only promote entries that actually carry a value under the convention;
                // an entry with a Name but no Value/OldValue/NewValue (e.g. AffectedItems)
                // is a regular object and must keep its own field names, or its contents
                // would be dropped entirely.
                let named = match item {
                    Value::Object(m) => m
                        .get("Name")
                        .and_then(|v| v.as_str())
                        .filter(|n| !n.is_empty())
                        .filter(|_| {
                            m.contains_key("Value")
                                || m.contains_key("OldValue")
                                || m.contains_key("NewValue")
                        }),
                    _ => None,
                };
                // Actor and Target are not really lists: each entry is one claim about a
                // single identity, keyed by Type. Collapsing them positionally produced a
                // joined string that could neither be matched ("Actor_ID:<one upn>" returns
                // nothing, because the stored value is the whole join) nor aggregated (every
                // bucket is a *combination* of identities). Keying by the type gives
                // Actor_UPN and Actor_Claim, which do both, and makes the field independent
                // of the order Microsoft happened to emit the claims in.
                if named.is_none() {
                    if let Some((id, type_value)) = identity_claim(item) {
                        let field = format!("{}_{}", prefix, identity_type_name(type_value));
                        flatten_value_into_gelf(id, &field, gelf, array_depth + 1);
                        // Several claims can share a type (Type 2, "Other", is a catch-all),
                        // so the array still needs its _json and _count companions.
                        any_collapsed = true;
                        continue;
                    }
                }
                match (named, item) {
                    (Some(name), Value::Object(m)) => {
                        // Promote directly as a top-level GELF field, dropping the container
                        // prefix (e.g. _ExtendedProperties_ApplicationDisplayName →
                        // _ApplicationDisplayName).
                        let base = format!("_{}", sanitize_field_segment(name));
                        if let Some(v) = m.get("Value") {
                            flatten_value_into_gelf(v, &base, gelf, array_depth + 1);
                        }
                        if let Some(v) = m.get("OldValue") {
                            flatten_value_into_gelf(v, &format!("{}_OldValue", base), gelf, array_depth + 1);
                        }
                        if let Some(v) = m.get("NewValue") {
                            flatten_value_into_gelf(v, &format!("{}_NewValue", base), gelf, array_depth + 1);
                        }
                    }
                    _ => {
                        // Collapse: every element writes to the same field name instead of
                        // `<prefix>_<i>`.  A positional suffix mints a brand-new field name
                        // for every array length ever seen, so the mapping grows without
                        // bound and eventually trips OpenSearch's `total_fields.limit`,
                        // which rejects the whole document.  Collapsing makes the field set
                        // a function of the audit schema rather than of the data.
                        any_collapsed = true;
                        flatten_value_into_gelf(item, prefix, gelf, array_depth + 1);
                    }
                }
            }
            // Collapsing loses which value belongs to which element — for a batched record
            // such as MailItemsAccessed, which Subject went with which item Id.  Keep the
            // original array verbatim alongside it so nothing is actually lost.  Only for
            // arrays that genuinely collapsed and hold more than one element: a single
            // element has no ordering to preserve, and fully promoted key/value arrays are
            // already reproduced field by field.
            if array_depth == 0 && any_collapsed && items.len() > 1 {
                if let Ok(raw) = serde_json::to_string(value) {
                    gelf.insert(format!("{}_json", prefix), Value::String(raw));
                }
            }
            // How many elements there were is a security signal in its own right: a bulk
            // delete (MoveToDeletedItems / SoftDelete / HardDelete over hundreds of items)
            // is what ransomware and mass-exfiltration look like in an audit feed.  The
            // collapsed fields cannot answer it — identical values are deduplicated, so a
            // record with 11 items and 9 distinct subjects yields 9 — so record the count
            // explicitly.  Kept a number so it can be range-queried and alerted on, and
            // summed rather than overwritten so a nested array reports the total across all
            // its parents (every FolderItem in the record, not just the last folder's).
            if any_collapsed {
                let key = format!("{}_count", prefix);
                let total = gelf
                    .get(&key)
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0)
                    + items.len() as u64;
                gelf.insert(key, Value::Number(total.into()));
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
                            flatten_value_into_gelf(&parsed, prefix, gelf, array_depth);
                            return;
                        }
                        _ => {}
                    }
                }
            }
            insert_or_append(gelf, prefix, value.clone(), array_depth);
        }
        Value::Number(_) => {
            insert_or_append(gelf, prefix, value.clone(), array_depth);
        }
        other => {
            insert_or_append(gelf, prefix, Value::String(other.to_string()), array_depth);
        }
    }
}

/// An `{"ID": ..., "Type": ...}` entry, as used by Actor and Target.
///
/// Requires exactly those two keys (OData annotations aside) so that an ordinary object
/// which happens to carry an `ID` and a `Type` is not mistaken for an identity claim.
fn identity_claim(item: &Value) -> Option<(&Value, &Value)> {
    let map = item.as_object()?;
    let significant = map.keys().filter(|k| !is_odata_annotation(k)).count();
    if significant != 2 {
        return None;
    }
    Some((map.get("ID")?, map.get("Type")?))
}

/// Name for an Office 365 `Identity` type, used as the field-name suffix for a claim.
///
/// Verified against live records: 0 is always the Entra object GUID, 5 always the UPN,
/// 1 an application display name, 2 a catch-all of GUIDs and free text. Unknown values
/// keep their number so a new enum member still lands in a stable, predictable field.
fn identity_type_name(type_value: &Value) -> String {
    match type_value.as_u64() {
        Some(0) => "Claim".to_string(),
        Some(1) => "Name".to_string(),
        Some(2) => "Other".to_string(),
        Some(3) => "PUID".to_string(),
        Some(4) => "SID".to_string(),
        Some(5) => "UPN".to_string(),
        Some(other) => format!("Type{}", other),
        None => match type_value.as_str().map(sanitize_field_segment) {
            Some(name) if !name.is_empty() => name,
            _ => "Type".to_string(),
        },
    }
}

/// Write `value` at `key`.
///
/// Outside an array this overwrites, preserving the previous behaviour.  Inside one,
/// several elements share a field name, so values accumulate into a single separated
/// string — always a string, never a bare number, so the field keeps one type across
/// every document (see `flatten_value_into_gelf`).  Repeats are dropped: the same value
/// twice in an array carries nothing and only inflates the message.
fn insert_or_append(gelf: &mut Map<String, Value>, key: &str, value: Value, array_depth: usize) {
    if array_depth == 0 {
        gelf.insert(key.to_string(), value);
        return;
    }
    let text = match &value {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    };
    match gelf.get_mut(key) {
        Some(Value::String(existing)) => {
            let separator = separator_for_depth(array_depth);
            if !existing.split(separator).any(|part| part == text) {
                existing.push_str(separator);
                existing.push_str(&text);
            }
        }
        Some(slot) => {
            *slot = Value::String(text);
        }
        None => {
            gelf.insert(key.to_string(), Value::String(text));
        }
    }
}

/// Recursively flatten a JSON object into GELF additional fields.
///
/// Each key in `map` is appended to `prefix` (separated by `_`) to form the GELF field name,
/// then delegated to `flatten_value_into_gelf` for further recursion.
/// `@`-prefixed OData annotation keys are skipped at every level.
fn flatten_object_into_gelf(
    map: &Map<String, Value>,
    prefix: &str,
    gelf: &mut Map<String, Value>,
    array_depth: usize,
) {
    for (key, value) in map {
        // Skip OData annotations – they are metadata noise, and `@` is not a legal
        // character in a GELF additional field name.  Graph emits them both as
        // standalone keys (`@odata.context`) and as suffixes on the property they
        // annotate (`RecordType@odata.type`), so a `starts_with` check is not enough.
        if is_odata_annotation(key) {
            continue;
        }
        let field_name = format!("{}_{}", prefix, sanitize_field_segment(key));
        flatten_value_into_gelf(value, &field_name, gelf, array_depth);
    }
}

/// True for OData annotation keys, which carry no audit data of their own:
/// `@odata.context`, `@odata.type`, `RecordType@odata.type`, …
fn is_odata_annotation(key: &str) -> bool {
    key.starts_with('@') || key.contains("@odata")
}

/// Coerce one field-name segment into something Graylog and OpenSearch can index.
///
/// GELF restricts additional field names to `[\w.-]`, and Graylog silently discards
/// fields that violate it — so names carrying spaces (`Included Updated Properties`,
/// promoted out of ModifiedProperties) never arrive at all.  Dots are legal GELF but
/// make OpenSearch build an object mapping for the part before the dot, which hard
/// -conflicts the moment that same name arrives as a scalar, so they are folded to
/// `_` as well.  Every run of illegal characters collapses into a single `_`.
fn sanitize_field_segment(segment: &str) -> String {
    let mut out = String::with_capacity(segment.len());
    let mut pending_sep = false;
    for ch in segment.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            if pending_sep && !out.is_empty() {
                out.push('_');
            }
            pending_sep = false;
            out.push(ch);
        } else {
            pending_sep = true;
        }
    }
    out
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
/// Produce one variant of `value` for each element of the array named `key`, wherever that
/// array sits in the tree.  Each variant keeps its element's full parent context, so an item
/// taken from `Folders[1].FolderItems[3]` still carries folder 1's path and metadata.
///
/// Returns `None` when `key` is absent, so the caller can try the next candidate.
fn split_value_on_key(value: &Value, key: &str) -> Option<Vec<Value>> {
    match value {
        Value::Object(map) => {
            if let Some(Value::Array(items)) = map.get(key) {
                if items.is_empty() {
                    return None;
                }
                return Some(
                    items
                        .iter()
                        .map(|item| {
                            let mut one = map.clone();
                            one.insert(key.to_string(), Value::Array(vec![item.clone()]));
                            Value::Object(one)
                        })
                        .collect(),
                );
            }
            // `Map` is ordered, so which branch matches does not vary between runs.
            for (child_key, child) in map {
                if let Some(variants) = split_value_on_key(child, key) {
                    return Some(
                        variants
                            .into_iter()
                            .map(|variant| {
                                let mut one = map.clone();
                                one.insert(child_key.clone(), variant);
                                Value::Object(one)
                            })
                            .collect(),
                    );
                }
            }
            None
        }
        Value::Array(items) => {
            // Elements that do not contain the key are carried through untouched rather than
            // dropped: a record with one folder holding three items and another holding none
            // must still account for both folders.
            let mut variants = Vec::new();
            let mut found = false;
            for item in items {
                match split_value_on_key(item, key) {
                    Some(inner) => {
                        found = true;
                        variants.extend(inner.into_iter().map(|v| Value::Array(vec![v])));
                    }
                    None => variants.push(Value::Array(vec![item.clone()])),
                }
            }
            if found {
                Some(variants)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Split one audit record into per-item records, using the first of `split_keys` that yields
/// more than one element.
fn split_log(log: &ArbitraryJson, split_keys: &[String]) -> Option<Vec<ArbitraryJson>> {
    // `ArbitraryJson` is a `HashMap`; sort so the same record always splits the same way.
    let mut field_names: Vec<&String> = log.keys().collect();
    field_names.sort();

    for key in split_keys {
        for field in &field_names {
            let variants = match split_value_on_key(&log[*field], key) {
                Some(v) if v.len() > 1 => v,
                _ => continue,
            };
            return Some(
                variants
                    .into_iter()
                    .map(|variant| {
                        let mut one = log.clone();
                        one.insert((*field).clone(), variant);
                        one
                    })
                    .collect(),
            );
        }
    }
    None
}

/// Build the GELF messages for one audit record.
///
/// A record describing several items -- `MailItemsAccessed` reports up to a dozen mails in a
/// single record -- becomes one message per item.  Collapsing them into shared fields would
/// otherwise lose which subject belonged to which message id, and deduplication would make
/// the item count unrecoverable.  `_ItemIndex` / `_ItemCount` mark each message's place, so a
/// bulk delete is still one query (`_ItemCount:>50`) without an aggregation.
pub fn build_gelf_messages(
    log: &ArbitraryJson,
    host: &str,
    split_keys: &[String],
    string_fields: &[String],
) -> Result<Vec<String>, std::io::Error> {
    let variants = match split_log(log, split_keys) {
        Some(v) => v,
        None => {
            let mut gelf = build_gelf_map(log, host)?;
            coerce_string_fields(&mut gelf, string_fields);
            return Ok(vec![serialize_gelf(&gelf)?]);
        }
    };

    let total = variants.len();
    let mut out = Vec::with_capacity(total);
    for (index, variant) in variants.iter().enumerate() {
        let mut gelf = build_gelf_map(variant, host)?;
        coerce_string_fields(&mut gelf, string_fields);
        gelf.insert("_ItemIndex".to_string(), Value::Number(index.into()));
        gelf.insert("_ItemCount".to_string(), Value::Number(total.into()));
        out.push(serialize_gelf(&gelf)?);
    }
    Ok(out)
}

/// Build a single GELF message, applying the default string-field coercion. Production
/// always goes through `build_gelf_messages`, which may emit several; this is the
/// single-message form the tests assert against.
#[cfg(test)]
pub fn build_gelf_message(log: &ArbitraryJson, host: &str) -> Result<String, std::io::Error> {
    let mut gelf = build_gelf_map(log, host)?;
    let defaults: Vec<String> = DEFAULT_STRING_FIELDS.iter().map(|s| s.to_string()).collect();
    coerce_string_fields(&mut gelf, &defaults);
    serialize_gelf(&gelf)
}

/// Force the named fields to text, whatever type the API sent.
///
/// Office 365 changes a field's type between record types -- `ListBaseType` is `1` on a
/// `FileAccessed` record and `"DocumentLibrary"` on a `ListViewed` one.  OpenSearch maps
/// the field from whichever document reaches it first and then rejects every document
/// carrying the other form, losing those records entirely; a scan of 2422 live records
/// found 320 numeric and 13 string occurrences of exactly this field.  Emitting it as text
/// consistently costs only range queries on what is an enum anyway.
///
/// Matching is on the field name's last segment, so a field is covered wherever it sits.
fn coerce_string_fields(gelf: &mut Map<String, Value>, string_fields: &[String]) {
    if string_fields.is_empty() {
        return;
    }
    for (key, value) in gelf.iter_mut() {
        if value.is_string() {
            continue;
        }
        let leaf = key.rsplit('_').next().unwrap_or(key.as_str());
        if string_fields.iter().any(|f| f == leaf) {
            *value = Value::String(value.to_string());
        }
    }
}

fn serialize_gelf(gelf: &Map<String, Value>) -> Result<String, std::io::Error> {
    serde_json::to_string(gelf)
        .map_err(|e| std::io::Error::new(ErrorKind::Other, format!("Could not serialize GELF message: {}", e)))
}

fn build_gelf_map(log: &ArbitraryJson, host: &str) -> Result<Map<String, Value>, std::io::Error> {

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

    // Pass 1: the record envelope.  Sorted so that field-name collisions resolve the same
    // way on every run — `ArbitraryJson` is a `HashMap`, whose iteration order is random.
    let mut envelope_keys: Vec<&String> = log
        .keys()
        // The GELF spec reserves `_id`; skip it to avoid conflicts with Graylog's internal id.
        .filter(|k| k.as_str() != "id" && k.as_str() != "auditData")
        .collect();
    envelope_keys.sort();
    for key in envelope_keys {
        // Recursively flatten every field.  This handles Office Management API records whose
        // top-level values may be nested objects, arrays of objects (e.g. `Parameters`,
        // `ExtendedProperties`, `Actor`, `Folders`), strings that embed JSON objects/arrays,
        // booleans, numbers, and nulls.  Null values are omitted; booleans are coerced to
        // their string representation; scalars are kept as-is; objects and arrays are
        // expanded with `_` / 0-based-index suffixes recursively so every leaf value becomes
        // its own searchable GELF field.
        if is_odata_annotation(key) {
            continue;
        }
        let gelf_key = format!("_{}", sanitize_field_segment(key));
        flatten_value_into_gelf(&log[key], &gelf_key, &mut gelf, 0);
    }

    // Pass 2: UALGraph records wrap the whole audit payload in a nested `auditData` object
    // (ClientIP, Operation, UserId, ObjectId, ApplicationDisplayName, …).  Flatten it to the
    // top level rather than under an `_auditData` prefix, so that a Graph UAL record and a
    // Management API record describing the same event expose the same field names and one
    // Graylog dashboard works across both inputs.
    //
    // The envelope wins any collision: it carries the normalised `CreationTime`
    // (`2026-09-22T11:18:13`, which Graylog parses) where `auditData` repeats it in Zulu
    // form, and its `Id` is the record id rather than a nested object's.
    if let Some(Value::Object(map)) = log.get("auditData") {
        let mut nested: Map<String, Value> = Map::new();
        flatten_object_into_gelf(map, "", &mut nested, 0);
        for (key, value) in nested {
            gelf.entry(key).or_insert(value);
        }
    }

    Ok(gelf)
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
        assert_eq!(parsed["_ClientIP"], "4.210.128.168", "_ClientIP must be a string");
        assert_eq!(parsed["_Operation"], "FileAccessedExtended", "_Operation must be a string");
        assert!(parsed["_RecordType"].is_number(), "_RecordType must be a number");
        // Nested objects are recursively flattened
        assert_eq!(parsed["_AppAccessContext_AADSessionId"], "abc",
            "_AppAccessContext_AADSessionId must be flattened from the nested object");
        assert_eq!(parsed["_AppAccessContext_ClientAppName"], "App Service",
            "_AppAccessContext_ClientAppName must be flattened from the nested object");
        assert!(parsed.get("_AppAccessContext").is_none(),
            "_AppAccessContext must not appear as a raw string after flattening");
        // odata type annotations are dropped
        assert!(parsed.get("_@odata.type").is_none(), "odata type annotations must be omitted");
        // Null sub-fields are omitted
        assert!(parsed.get("_NullField").is_none(), "null auditData fields must be omitted");
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
        assert_eq!(parsed["_AppAccessContext_AADSessionId"], "004db2b9-de97-c009-44f9-214e4f43b48d");
        assert_eq!(parsed["_AppAccessContext_ClientAppName"], "rclone");
        // OData annotation inside the string-encoded object must also be dropped
        assert!(parsed.get("_AppAccessContext_@odata.type").is_none(),
            "odata annotations inside string-encoded nested objects must be omitted");
        // The raw string field must not appear
        assert!(parsed.get("_AppAccessContext").is_none(),
            "_AppAccessContext must not appear as a raw string");
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
        // All elements collapse onto one field name per leaf property, accumulating into a
        // multi-value field; a positional suffix would mint a new field name per array
        // length and grow the OpenSearch mapping without bound.
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
        assert!(parsed.get("_Folders").is_none(),
            "_Folders must be flattened, not stored as an array string");
        // Both folders' ids accumulate into one multi-value field, in order.
        assert_eq!(parsed["_Folders_Id"], "folder-001; folder-002");
        // Nested arrays collapse the same way, across both levels of nesting.
        // depth 2: the inner separator, so element boundaries stay distinguishable
        assert_eq!(parsed["_Folders_FolderItems_Id"], "item-001, item-002");
        assert_eq!(parsed["_Folders_FolderItems_CreationTime"],
            "2026-04-25T05:33:44Z, 2026-04-25T05:33:45Z");
        // Collapsing loses which item sat in which folder; the raw array keeps it. Only the
        // outermost array gets a companion -- the nested one is already inside it.
        let raw = parsed["_Folders_json"].as_str().expect("_Folders_json must be present");
        assert!(raw.contains("item-002") && raw.contains("folder-002"));
        assert!(parsed.get("_Folders_FolderItems_json").is_none(),
            "nested arrays must not each get their own companion");
        // No positional field name may survive.
        for k in parsed.as_object().unwrap().keys() {
            assert!(!k.split('_').any(|p| p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty()),
                "positional field name leaked: {}", k);
        }
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
        assert!(parsed.get("_Folders").is_none(),
            "_Folders must not appear as a raw string");
        assert_eq!(parsed["_Folders_Id"], "folder-str-001");
        assert_eq!(parsed["_Folders_FolderItems_Id"], "item-str-001");
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

    /// Graph UAL records wrap the payload in `auditData`; Management API records carry the
    /// same fields at the top level. Both must produce the same GELF field names so a single
    /// Graylog dashboard works across the two inputs.
    #[test]
    fn gelf_message_promotes_audit_data_to_top_level() {
        let mut log = make_log("FileAccessed", "2026-09-22T11:18:13");
        log.insert("auditData".to_string(), serde_json::json!({
            "ApplicationDisplayName": "OneDrive SyncEngine",
            "ClientIP": "1.2.3.4",
            "AppAccessContext": {"ClientAppName": "rclone"},
        }));
        let parsed: Value = serde_json::from_str(
            &build_gelf_message(&log, "h").unwrap()).unwrap();

        assert_eq!(parsed["_ApplicationDisplayName"], "OneDrive SyncEngine");
        assert_eq!(parsed["_ClientIP"], "1.2.3.4");
        assert_eq!(parsed["_AppAccessContext_ClientAppName"], "rclone");
        assert!(parsed.get("_auditData_ApplicationDisplayName").is_none(),
            "the auditData prefix must not survive");
    }

    /// The envelope carries the normalised CreationTime that Graylog can parse; auditData
    /// repeats it in Zulu form. The envelope must win, deterministically.
    #[test]
    fn gelf_message_envelope_wins_collision_with_audit_data() {
        let mut log = make_log("FileAccessed", "2026-09-22T11:18:13");
        log.insert("auditData".to_string(), serde_json::json!({
            "CreationTime": "2026-09-22T11:18:13Z",
            "UserId": "other@example.com",
        }));
        for _ in 0..20 {
            let parsed: Value = serde_json::from_str(
                &build_gelf_message(&log, "h").unwrap()).unwrap();
            assert_eq!(parsed["_CreationTime"], "2026-09-22T11:18:13");
            assert_eq!(parsed["_UserId"], "user@example.com");
        }
    }

    /// Graph emits OData annotations as suffixes (`RecordType@odata.type`), not just as
    /// standalone `@`-prefixed keys. `@` is illegal in a GELF field name, so Graylog discards
    /// these; they are type metadata and carry no audit data.
    #[test]
    fn gelf_message_drops_odata_annotation_suffixes() {
        let mut log = make_log("FileAccessed", "2026-09-22T11:18:13");
        log.insert("auditData".to_string(), serde_json::json!({
            "RecordType": 6,
            "RecordType@odata.type": "#Int32",
            "ListBaseType@odata.type": "#Int32",
            "@odata.context": "https://graph.microsoft.com/beta/$metadata",
        }));
        let parsed: Value = serde_json::from_str(
            &build_gelf_message(&log, "h").unwrap()).unwrap();

        assert_eq!(parsed["_RecordType"], 6);
        for k in parsed.as_object().unwrap().keys() {
            assert!(!k.contains('@'), "no field name may contain '@': {}", k);
        }
    }

    /// GELF restricts additional field names to `[\w.-]`, and OpenSearch treats a dot as an
    /// object separator. Names promoted out of ModifiedProperties contain both spaces and
    /// dots, so every segment is folded to `[A-Za-z0-9_]`.
    #[test]
    fn gelf_message_sanitizes_illegal_field_name_characters() {
        let mut log = make_log("Update group.", "2026-09-22T11:18:13");
        log.insert("ModifiedProperties".to_string(), serde_json::json!([
            {"Name": "Included Updated Properties", "NewValue": "DisplayName"},
            {"Name": "Group.DisplayName", "NewValue": "Sales"},
        ]));
        let parsed: Value = serde_json::from_str(
            &build_gelf_message(&log, "h").unwrap()).unwrap();

        assert_eq!(parsed["_Included_Updated_Properties_NewValue"], "DisplayName");
        assert_eq!(parsed["_Group_DisplayName_NewValue"], "Sales");
        for k in parsed.as_object().unwrap().keys() {
            assert!(k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'),
                "illegal character in field name: {}", k);
        }
    }

    /// One malformed entry used to demote the whole array to positional names, turning
    /// `ApplicationDisplayName` from a field into a *value* and hiding it from aggregations.
    #[test]
    fn gelf_message_promotes_named_entries_despite_unnamed_siblings() {
        let mut log = make_log("FileAccessed", "2026-09-22T11:18:13");
        log.insert("ExtendedProperties".to_string(), serde_json::json!([
            {"Name": "ApplicationDisplayName", "Value": "Browser"},
            {"Value": "entry with no name"},
        ]));
        let parsed: Value = serde_json::from_str(
            &build_gelf_message(&log, "h").unwrap()).unwrap();

        assert_eq!(parsed["_ApplicationDisplayName"], "Browser");
        assert_eq!(parsed["_ExtendedProperties_Value"], "entry with no name");
    }

    /// An entry with a `Name` but no `Value`/`OldValue`/`NewValue` is an ordinary object
    /// (e.g. AffectedItems), not a key/value pair. Treating it as one would drop its contents.
    #[test]
    fn gelf_message_keeps_objects_that_have_a_name_but_no_value() {
        let mut log = make_log("HardDelete", "2026-09-22T11:18:13");
        log.insert("AffectedItems".to_string(), serde_json::json!([
            {"Name": "report.xlsx", "Id": "item-001", "ParentFolder": "Inbox"},
        ]));
        let parsed: Value = serde_json::from_str(
            &build_gelf_message(&log, "h").unwrap()).unwrap();

        assert_eq!(parsed["_AffectedItems_Name"], "report.xlsx");
        assert_eq!(parsed["_AffectedItems_Id"], "item-001");
        assert_eq!(parsed["_AffectedItems_ParentFolder"], "Inbox");
    }

    /// Collapsed arrays accumulate: distinct values join, repeats are dropped, and a
    /// single value stays a plain scalar.
    #[test]
    fn gelf_message_accumulates_collapsed_array_values() {
        let mut log = make_log("FileAccessed", "2026-09-22T11:18:13");
        log.insert("Shares".to_string(), serde_json::json!([
            {"SiteUrl": "https://a", "Role": 5},
            {"SiteUrl": "https://b", "Role": 5},
            {"SiteUrl": "https://a", "Role": 0},
        ]));
        log.insert("Folders".to_string(), serde_json::json!([{"Path": "only-one"}]));
        let parsed: Value = serde_json::from_str(
            &build_gelf_message(&log, "h").unwrap()).unwrap();

        assert_eq!(parsed["_Shares_SiteUrl"], "https://a; https://b");
        // Numbers from inside an array are written as text even when they collapse to one
        // value, so the field cannot flip between long and keyword across documents.
        assert_eq!(parsed["_Shares_Role"], "5; 0");
        assert_eq!(parsed["_Folders_Path"], "only-one");
        assert!(parsed["_Folders_Path"].is_string(), "single-element arrays are still text");
        assert!(parsed["_Shares_json"].as_str().unwrap().contains("https://b"));
        assert!(parsed.get("_Folders_json").is_none(),
            "a single-element array has no ordering worth preserving");
    }

    /// Actor and Target entries are claims about one identity, keyed by Type. Keying the
    /// field by the type is what makes them matchable and aggregatable: the old joined
    /// Actor_ID could not be matched against a single UPN, and aggregating it bucketed by
    /// *combination* of identities rather than by identity.
    #[test]
    fn gelf_message_keys_identity_claims_by_type() {
        let mut log = make_log("Add group.", "2026-09-22T11:18:13");
        log.insert("auditData".to_string(), serde_json::json!({
            "Actor": [
                {"ID": "6275b706-fc76-436f-bff6-be9ae4023015", "Type": 0,
                 "Type@odata.type": "#Int64"},
                {"ID": "kovalik.ext@example.com", "Type": 5},
            ],
            "Target": [
                {"ID": "Microsoft.Azure.SyncFabric", "Type": 1},
                {"ID": "ServicePrincipal", "Type": 2},
                {"ID": "NotAgentic", "Type": 2},
            ],
        }));
        let parsed: Value = serde_json::from_str(
            &build_gelf_message(&log, "h").unwrap()).unwrap();

        assert_eq!(parsed["_Actor_Claim"], "6275b706-fc76-436f-bff6-be9ae4023015");
        assert_eq!(parsed["_Actor_UPN"], "kovalik.ext@example.com");
        assert_eq!(parsed["_Target_Name"], "Microsoft.Azure.SyncFabric");
        // Type 2 is a catch-all, so several claims can share it and still collapse.
        assert_eq!(parsed["_Target_Other"], "ServicePrincipal; NotAgentic");
        // The positional pair it replaces must be gone.
        assert!(parsed.get("_Actor_ID").is_none() && parsed.get("_Actor_Type").is_none(),
            "the joined ID/Type pair is replaced, not duplicated");
        // The raw array is still kept for reconstruction.
        assert!(parsed["_Actor_json"].as_str().unwrap().contains("kovalik.ext@example.com"));
    }

    /// An unknown Type must still land in a stable field rather than being dropped, and an
    /// object that merely happens to carry an ID and a Type is not an identity claim.
    #[test]
    fn gelf_message_identity_promotion_is_conservative() {
        let mut log = make_log("Add group.", "2026-09-22T11:18:13");
        log.insert("Actor".to_string(), serde_json::json!([{"ID": "x", "Type": 97}]));
        log.insert("Items".to_string(), serde_json::json!([
            {"ID": "i-1", "Type": 5, "Subject": "not an identity"},
        ]));
        let parsed: Value = serde_json::from_str(
            &build_gelf_message(&log, "h").unwrap()).unwrap();

        assert_eq!(parsed["_Actor_Type97"], "x", "unknown enum members keep their number");
        assert_eq!(parsed["_Items_ID"], "i-1", "a third field means it is a normal object");
        assert_eq!(parsed["_Items_Subject"], "not an identity");
    }

    /// A bulk delete is what ransomware looks like in an audit feed, so the number of
    /// elements must survive collapsing. It cannot be recovered from the collapsed fields:
    /// identical values are deduplicated, and nested arrays must report the total across
    /// every parent rather than just the last one.
    #[test]
    fn gelf_message_records_collapsed_array_element_counts() {
        let mut log = make_log("HardDelete", "2026-09-22T11:18:13");
        log.insert("auditData".to_string(), serde_json::json!({
            "Folders": [
                {"Id": "f1", "FolderItems": [
                    {"Subject": "dup"}, {"Subject": "dup"}, {"Subject": "other"}]},
                {"Id": "f2", "FolderItems": [{"Subject": "third"}]},
            ]
        }));
        let parsed: Value = serde_json::from_str(
            &build_gelf_message(&log, "h").unwrap()).unwrap();

        // Four items across two folders, even though only three subjects are distinct.
        assert_eq!(parsed["_Folders_count"], 2);
        assert_eq!(parsed["_Folders_FolderItems_count"], 4);
        assert_eq!(parsed["_Folders_FolderItems_Subject"], "dup, other, third");
        // Counts stay numeric so `_count:>100` can be alerted on.
        assert!(parsed["_Folders_FolderItems_count"].is_number());
    }

    fn split_keys() -> Vec<String> {
        DEFAULT_SPLIT_ARRAYS.iter().map(|s| s.to_string()).collect()
    }

    fn string_fields() -> Vec<String> {
        DEFAULT_STRING_FIELDS.iter().map(|s| s.to_string()).collect()
    }

    fn parse_all(msgs: Vec<String>) -> Vec<Value> {
        msgs.iter().map(|m| serde_json::from_str(m).unwrap()).collect()
    }

    /// A Bind record reports many mails in one audit record. One message per mail keeps the
    /// subject with its own message id, which collapsing cannot do.
    #[test]
    fn gelf_splits_mail_items_into_one_message_per_item() {
        let mut log = make_log("MailItemsAccessed", "2026-09-22T11:18:13");
        log.insert("auditData".to_string(), serde_json::json!({
            "MailAccessType": "Bind",
            "ClientIP": "1.2.3.4",
            "Folders": [{
                "Path": "\\Inbox",
                "FolderItems": [
                    {"Subject": "first",  "InternetMessageId": "<a@x>"},
                    {"Subject": "second", "InternetMessageId": "<b@x>"},
                    {"Subject": "third",  "InternetMessageId": "<c@x>"},
                ]
            }]
        }));
        let msgs = parse_all(build_gelf_messages(&log, "h", &split_keys(), &string_fields()).unwrap());

        assert_eq!(msgs.len(), 3, "one message per mail item");
        for (i, m) in msgs.iter().enumerate() {
            assert_eq!(m["_ItemIndex"], i);
            assert_eq!(m["_ItemCount"], 3);
            // the record-level context is repeated on every message
            assert_eq!(m["_ClientIP"], "1.2.3.4");
            assert_eq!(m["_Folders_Path"], "\\Inbox");
        }
        // each subject stays paired with its own message id
        assert_eq!(msgs[0]["_Folders_FolderItems_Subject"], "first");
        assert_eq!(msgs[0]["_Folders_FolderItems_InternetMessageId"], "<a@x>");
        assert_eq!(msgs[2]["_Folders_FolderItems_Subject"], "third");
        assert_eq!(msgs[2]["_Folders_FolderItems_InternetMessageId"], "<c@x>");
    }

    /// A Sync record has no FolderItems at all -- Outlook pulled whole folders down, so no
    /// per-message ids exist. Splitting must fall through to one message per folder instead
    /// of silently emitting a single message that hides how much was synchronised.
    #[test]
    fn gelf_splits_sync_records_per_folder() {
        let mut log = make_log("MailItemsAccessed", "2026-09-22T11:18:13");
        log.insert("auditData".to_string(), serde_json::json!({
            "MailAccessType": "Sync",
            "Folders": [{"Path": "\\Inbox"}, {"Path": "\\Sent Items"}]
        }));
        let msgs = parse_all(build_gelf_messages(&log, "h", &split_keys(), &string_fields()).unwrap());

        assert_eq!(msgs.len(), 2, "one message per synchronised folder");
        assert_eq!(msgs[0]["_Folders_Path"], "\\Inbox");
        assert_eq!(msgs[1]["_Folders_Path"], "\\Sent Items");
        for m in &msgs {
            assert_eq!(m["_MailAccessType"], "Sync");
            assert!(m.get("_Folders_FolderItems_InternetMessageId").is_none(),
                "a Sync carries no per-message ids");
        }
    }

    /// Items spread across several folders must all survive, each keeping its own folder.
    #[test]
    fn gelf_splits_items_across_multiple_folders() {
        let mut log = make_log("MailItemsAccessed", "2026-09-22T11:18:13");
        log.insert("auditData".to_string(), serde_json::json!({
            "Folders": [
                {"Path": "\\Inbox", "FolderItems": [{"Subject": "a"}, {"Subject": "b"}]},
                {"Path": "\\Archive", "FolderItems": [{"Subject": "c"}]},
            ]
        }));
        let msgs = parse_all(build_gelf_messages(&log, "h", &split_keys(), &string_fields()).unwrap());

        assert_eq!(msgs.len(), 3, "a folder holding a single item must not be dropped");
        let pairs: Vec<(String, String)> = msgs.iter().map(|m| (
            m["_Folders_Path"].as_str().unwrap().to_string(),
            m["_Folders_FolderItems_Subject"].as_str().unwrap().to_string(),
        )).collect();
        assert!(pairs.contains(&("\\Inbox".into(), "a".into())));
        assert!(pairs.contains(&("\\Inbox".into(), "b".into())));
        assert!(pairs.contains(&("\\Archive".into(), "c".into())));
    }

    /// Records with nothing to split stay exactly one message.
    #[test]
    fn gelf_does_not_split_records_without_item_arrays() {
        let mut log = make_log("FileAccessed", "2026-09-22T11:18:13");
        log.insert("auditData".to_string(),
            serde_json::json!({"ApplicationDisplayName": "Browser"}));
        let msgs = build_gelf_messages(&log, "h", &split_keys(), &string_fields()).unwrap();

        assert_eq!(msgs.len(), 1);
        let m: Value = serde_json::from_str(&msgs[0]).unwrap();
        assert_eq!(m["_ApplicationDisplayName"], "Browser");
        assert!(m.get("_ItemIndex").is_none(), "no split, no item markers");
    }

    /// A one-item array is not worth splitting, and must not be.
    #[test]
    fn gelf_does_not_split_single_element_arrays() {
        let mut log = make_log("HardDelete", "2026-09-22T11:18:13");
        log.insert("auditData".to_string(), serde_json::json!({
            "AffectedItems": [{"Subject": "only-one"}]
        }));
        let msgs = build_gelf_messages(&log, "h", &split_keys(), &string_fields()).unwrap();
        assert_eq!(msgs.len(), 1);
    }

    /// Office 365 sends ListBaseType as a number on FileAccessed and as text on ListViewed.
    /// OpenSearch maps the field from whichever arrives first and rejects the rest, so the
    /// collector must pick one type and stick to it.
    #[test]
    fn gelf_coerces_inconsistently_typed_fields_to_text() {
        let mut numeric = make_log("FileAccessed", "2026-09-22T11:18:13");
        numeric.insert("auditData".to_string(),
            serde_json::json!({"ListBaseType": 1, "ItemCount": 7}));
        let a: Value = serde_json::from_str(&build_gelf_message(&numeric, "h").unwrap()).unwrap();

        let mut textual = make_log("ListViewed", "2026-09-22T11:18:13");
        textual.insert("auditData".to_string(),
            serde_json::json!({"ListBaseType": "DocumentLibrary"}));
        let b: Value = serde_json::from_str(&build_gelf_message(&textual, "h").unwrap()).unwrap();

        assert_eq!(a["_ListBaseType"], "1", "the numeric form must be emitted as text");
        assert_eq!(b["_ListBaseType"], "DocumentLibrary");
        assert!(a["_ListBaseType"].is_string() && b["_ListBaseType"].is_string(),
            "both record types must agree on the field's type");
        // Fields not on the list keep their natural type, so ranges still work.
        assert!(a["_ItemCount"].is_number());
    }

    /// An empty list disables coercion; an explicit list replaces the default.
    #[test]
    fn gelf_string_field_coercion_is_configurable() {
        let mut log = make_log("FileAccessed", "2026-09-22T11:18:13");
        log.insert("auditData".to_string(), serde_json::json!({"ListBaseType": 1, "Version": 2}));

        let none: Value = serde_json::from_str(
            &build_gelf_messages(&log, "h", &split_keys(), &[]).unwrap()[0]).unwrap();
        assert!(none["_ListBaseType"].is_number(), "empty list leaves types untouched");

        let custom = vec!["Version".to_string()];
        let v: Value = serde_json::from_str(
            &build_gelf_messages(&log, "h", &split_keys(), &custom).unwrap()[0]).unwrap();
        assert_eq!(v["_Version"], "2");
        assert!(v["_ListBaseType"].is_number(), "not on the custom list");
    }
}
