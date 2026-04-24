use crate::data_structures::ArbitraryJson;
use chrono::{DateTime, NaiveDateTime, Utc};
use serde_derive::Deserialize;
use std::collections::HashMap;
use std::ffi::OsString;
use std::fs::File;
use std::io::{BufReader, LineWriter, Read, Write};
use std::path::Path;

#[derive(Deserialize, Clone, Debug)]
pub struct Config {
    pub log: Option<LogSubConfig>,
    pub collect: CollectSubConfig,
    pub output: OutputSubConfig,
}
impl Config {
    pub fn new(path: String) -> Self {
        let open_file = File::open(path)
            .unwrap_or_else(|e| panic!("Config path could not be opened: {}", e.to_string()));
        let reader = BufReader::new(open_file);
        let config: Config = serde_yaml::from_reader(reader)
            .unwrap_or_else(|e| panic!("Config could not be parsed: {}", e.to_string()));
        config
    }

    pub fn get_needed_runs(&self) -> HashMap<String, Vec<(String, String)>> {
        let mut runs: HashMap<String, Vec<(String, String)>> = HashMap::new();
        for content_type in self.collect.content_types.get_management_content_type_strings() {
            runs.insert(content_type, self.get_management_time_ranges());
        }
        for content_type in self.collect.content_types.get_graph_content_type_strings() {
            runs.insert(content_type, self.get_time_ranges());
        }
        runs
    }

    pub fn get_management_time_ranges(&self) -> Vec<(String, String)> {
        let hours_to_collect = self.collect.hours_to_collect.unwrap_or(24);
        if hours_to_collect > 168 {
            panic!("Hours to collect cannot be more than 168 for Office Management API content types");
        }
        self.get_time_ranges()
    }

    pub fn get_time_ranges(&self) -> Vec<(String, String)> {
        let end_time = chrono::Utc::now();
        let hours_to_collect = self.collect.hours_to_collect.unwrap_or(24);
        let mut ranges = Vec::new();
        let mut start_time = end_time - chrono::Duration::try_hours(hours_to_collect).unwrap();
        while end_time - start_time > chrono::Duration::try_hours(24).unwrap() {
            let split_end_time = start_time + chrono::Duration::try_hours(24).unwrap();
            let formatted_start_time = start_time.format("%Y-%m-%dT%H:%M:%SZ").to_string();
            let formatted_end_time = split_end_time.format("%Y-%m-%dT%H:%M:%SZ").to_string();
            ranges.push((formatted_start_time, formatted_end_time));
            start_time = split_end_time;
        }
        let formatted_start_time = start_time.format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let formatted_end_time = end_time.format("%Y-%m-%dT%H:%M:%SZ").to_string();
        ranges.push((formatted_start_time, formatted_end_time));
        ranges
    }

    pub fn load_known_blobs(&self) -> HashMap<String, String> {
        let working_dir = if let Some(i) = &self.collect.working_dir {
            i.as_str()
        } else {
            "./"
        };

        let file_name = Path::new("known_blobs");
        let mut path = Path::new(working_dir).join(file_name);
        self.load_known_content(path.as_mut_os_string())
    }

    pub fn save_known_blobs(&mut self, known_blobs: &HashMap<String, String>) {
        let mut known_blobs_path = Path::new(
            self.collect
                .working_dir
                .as_ref()
                .unwrap_or(&"./".to_string()),
        )
        .join(Path::new("known_blobs"));
        self.save_known_content(known_blobs, &known_blobs_path.as_mut_os_string())
    }

    fn load_known_content(&self, path: &OsString) -> HashMap<String, String> {
        let mut known_content = HashMap::new();
        if !Path::new(path).exists() {
            return known_content;
        }

        // Load file
        let mut known_content_file = File::open(path).unwrap();
        let mut known_content_string = String::new();
        known_content_file
            .read_to_string(&mut known_content_string)
            .unwrap();
        for line in known_content_string.lines() {
            if line.trim().is_empty() {
                continue;
            }
            // Skip load expired content
            let now = Utc::now();
            if let Some((id, creation_time)) = line.split_once(',') {
                let invalidated = if let Ok(i) =
                    NaiveDateTime::parse_from_str(creation_time, "%Y-%m-%dT%H:%M:%S.%fZ")
                {
                    let time_utc = DateTime::<Utc>::from_naive_utc_and_offset(i, Utc);
                    now >= time_utc
                } else {
                    true
                };
                if !invalidated {
                    known_content.insert(id.trim().to_string(), creation_time.trim().to_string());
                }
            }
        }
        known_content
    }

    fn save_known_content(&mut self, known_content: &HashMap<String, String>, path: &OsString) {
        let known_content_file = File::create(path).unwrap();
        let mut writer = LineWriter::new(known_content_file);

        for (id, creation_time) in known_content.iter() {
            writer
                .write_all(format!("{},{}\n", id, creation_time).as_bytes())
                .unwrap();
        }
        writer.flush().unwrap();
    }
}

#[derive(Deserialize, Clone, Debug)]
pub struct LogSubConfig {
    pub path: String,
    pub debug: bool,
}

#[derive(Deserialize, Clone, Debug)]
pub struct CollectSubConfig {
    #[serde(rename = "workingDir")]
    pub working_dir: Option<String>,
    #[serde(rename = "cacheSize")]
    pub cache_size: Option<usize>,
    #[serde(rename = "contentTypes")]
    pub content_types: ContentTypesSubConfig,
    #[serde(rename = "maxThreads")]
    pub max_threads: Option<usize>,
    #[serde(rename = "globalTimeout")]
    pub global_timeout: Option<usize>,
    pub retries: Option<usize>,
    #[serde(rename = "hoursToCollect")]
    pub hours_to_collect: Option<i64>,
    #[serde(rename = "skipKnownLogs")]
    pub skip_known_logs: Option<bool>,
    #[serde(rename = "entraCategories")]
    pub entra_categories: Option<Vec<String>>,
    pub filter: Option<FilterSubConfig>,
    pub duplicate: Option<usize>,
}
#[derive(Deserialize, Copy, Clone, Debug)]
pub struct ContentTypesSubConfig {
    #[serde(rename = "Audit.General")]
    pub general: Option<bool>,
    #[serde(rename = "Audit.AzureActiveDirectory")]
    pub azure_active_directory: Option<bool>,
    #[serde(rename = "Audit.Exchange")]
    pub exchange: Option<bool>,
    #[serde(rename = "Audit.SharePoint")]
    pub share_point: Option<bool>,
    #[serde(rename = "DLP.All")]
    pub dlp: Option<bool>,
    #[serde(rename = "Audit.UALGraph")]
    pub ual_graph: Option<bool>,
    #[serde(rename = "Audit.EntraID")]
    pub entra_id: Option<bool>,
    #[serde(rename = "Audit.EntraIDSignIns")]
    pub entra_id_sign_ins: Option<bool>,
    #[serde(rename = "Audit.ExchangeMailboxGraph")]
    pub exchange_mailbox_graph: Option<bool>,
    #[serde(rename = "Audit.Intune")]
    pub intune: Option<bool>,
    #[serde(rename = "Audit.IdentityProtectionRiskDetections")]
    pub identity_protection_risk_detections: Option<bool>,
}
impl ContentTypesSubConfig {
    pub fn get_management_content_type_strings(&self) -> Vec<String> {
        let mut results = Vec::new();
        if self.general.unwrap_or(false) {
            results.push("Audit.General".to_string())
        }
        if self.azure_active_directory.unwrap_or(false) {
            results.push("Audit.AzureActiveDirectory".to_string())
        }
        if self.exchange.unwrap_or(false) {
            results.push("Audit.Exchange".to_string())
        }
        if self.share_point.unwrap_or(false) {
            results.push("Audit.SharePoint".to_string())
        }
        if self.dlp.unwrap_or(false) {
            results.push("DLP.All".to_string())
        }
        results
    }

    pub fn graph_ual_enabled(&self) -> bool {
        self.ual_graph.unwrap_or(false)
    }

    pub fn entra_id_enabled(&self) -> bool {
        self.entra_id.unwrap_or(false)
    }

    pub fn entra_id_sign_ins_enabled(&self) -> bool {
        self.entra_id_sign_ins.unwrap_or(false)
    }

    pub fn exchange_mailbox_graph_enabled(&self) -> bool {
        self.exchange_mailbox_graph.unwrap_or(false)
    }

    pub fn intune_enabled(&self) -> bool {
        self.intune.unwrap_or(false)
    }

    pub fn identity_protection_risk_detections_enabled(&self) -> bool {
        self.identity_protection_risk_detections.unwrap_or(false)
    }

    pub fn get_content_type_strings(&self) -> Vec<String> {
        let mut results = self.get_management_content_type_strings();
        results.extend(self.get_graph_content_type_strings());
        results
    }

    pub fn get_graph_content_type_strings(&self) -> Vec<String> {
        let mut results = Vec::new();
        if self.graph_ual_enabled() {
            results.push("UALGraph".to_string());
        }
        if self.entra_id_sign_ins_enabled() {
            results.push("EntraID.SignIns".to_string());
        }
        if self.entra_id_enabled() {
            results.push("EntraID.DirectoryAudits".to_string());
        }
        if self.exchange_mailbox_graph_enabled() {
            results.push("ExchangeMailbox.Graph".to_string());
        }
        if self.intune_enabled() {
            results.push("Intune".to_string());
        }
        if self.identity_protection_risk_detections_enabled() {
            results.push("IdentityProtection.RiskDetections".to_string());
        }
        results
    }
}

#[derive(Deserialize, Clone, Debug)]
pub struct FilterSubConfig {
    #[serde(rename = "Audit.General")]
    pub general: Option<ArbitraryJson>,
    #[serde(rename = "Audit.AzureActiveDirectory")]
    pub azure_active_directory: Option<ArbitraryJson>,
    #[serde(rename = "Audit.Exchange")]
    pub exchange: Option<ArbitraryJson>,
    #[serde(rename = "Audit.SharePoint")]
    pub share_point: Option<ArbitraryJson>,
    #[serde(rename = "DLP.All")]
    pub dlp: Option<ArbitraryJson>,
    #[serde(rename = "Audit.UALGraph")]
    pub ual_graph: Option<ArbitraryJson>,
    #[serde(rename = "Audit.EntraID")]
    pub entra_id: Option<ArbitraryJson>,
    #[serde(rename = "Audit.EntraIDSignIns")]
    pub entra_id_sign_ins: Option<ArbitraryJson>,
    #[serde(rename = "Audit.ExchangeMailboxGraph")]
    pub exchange_mailbox_graph: Option<ArbitraryJson>,
    #[serde(rename = "Audit.Intune")]
    pub intune: Option<ArbitraryJson>,
    #[serde(rename = "Audit.IdentityProtectionRiskDetections")]
    pub identity_protection_risk_detections: Option<ArbitraryJson>,
}
impl FilterSubConfig {
    pub fn get_filters(&self) -> HashMap<String, ArbitraryJson> {
        let mut results = HashMap::new();
        if let Some(filter) = self.general.as_ref() {
            results.insert("Audit.General".to_string(), filter.clone());
        }
        if let Some(filter) = self.azure_active_directory.as_ref() {
            results.insert("Audit.AzureActiveDirectory".to_string(), filter.clone());
        }
        if let Some(filter) = self.share_point.as_ref() {
            results.insert("Audit.SharePoint".to_string(), filter.clone());
        }
        if let Some(filter) = self.exchange.as_ref() {
            results.insert("Audit.Exchange".to_string(), filter.clone());
        }
        if let Some(filter) = self.dlp.as_ref() {
            results.insert("DLP.All".to_string(), filter.clone());
        }
        if let Some(filter) = self.ual_graph.as_ref() {
            results.insert("UALGraph".to_string(), filter.clone());
        }
        if let Some(filter) = self.entra_id_sign_ins.as_ref() {
            results.insert("EntraID.SignIns".to_string(), filter.clone());
        }
        if let Some(filter) = self.entra_id.as_ref() {
            results.insert("EntraID.DirectoryAudits".to_string(), filter.clone());
        }
        if let Some(filter) = self.exchange_mailbox_graph.as_ref() {
            results.insert("ExchangeMailbox.Graph".to_string(), filter.clone());
        }
        if let Some(filter) = self.intune.as_ref() {
            results.insert("Intune".to_string(), filter.clone());
        }
        if let Some(filter) = self.identity_protection_risk_detections.as_ref() {
            results.insert("IdentityProtection.RiskDetections".to_string(), filter.clone());
        }
        results
    }
}

#[derive(Deserialize, Clone, Debug)]
pub struct OutputSubConfig {
    pub file: Option<FileOutputSubConfig>,
    pub graylog: Option<GraylogOutputSubConfig>,
    pub fluentd: Option<FluentdOutputSubConfig>,
    #[serde(rename = "azureLogAnalytics")]
    pub oms: Option<OmsOutputSubConfig>,
}

#[derive(Deserialize, Clone, Debug)]
pub struct FileOutputSubConfig {
    pub path: String,
    #[serde(rename = "separateByContentType")]
    pub separate_by_content_type: Option<bool>,
    #[allow(dead_code)] // documented in config examples; custom CSV separator, not yet implemented
    pub separator: Option<String>,
}

#[derive(Deserialize, Clone, Debug)]
pub struct GraylogOutputSubConfig {
    pub address: String,
    pub port: u16,
}

#[derive(Deserialize, Clone, Debug)]
pub struct FluentdOutputSubConfig {
    #[serde(rename = "tenantName")]
    pub tenant_name: String,
    pub address: String,
    pub port: u16,
}

#[derive(Deserialize, Clone, Debug)]
pub struct OmsOutputSubConfig {
    #[serde(rename = "workspaceId")]
    pub workspace_id: String,
}

#[cfg(test)]
mod tests {
    use crate::config::ContentTypesSubConfig;

    #[test]
    fn includes_graph_content_type_when_enabled() {
        let content_types = ContentTypesSubConfig {
            general: Some(true),
            azure_active_directory: None,
            exchange: None,
            share_point: None,
            dlp: None,
            ual_graph: Some(true),
            entra_id: Some(true),
            entra_id_sign_ins: Some(true),
            exchange_mailbox_graph: None,
            intune: None,
            identity_protection_risk_detections: None,
        };

        assert_eq!(
            content_types.get_content_type_strings(),
            vec![
                "Audit.General".to_string(),
                "UALGraph".to_string(),
                "EntraID.SignIns".to_string(),
                "EntraID.DirectoryAudits".to_string()
            ]
        );
        assert_eq!(
            content_types.get_management_content_type_strings(),
            vec!["Audit.General".to_string()]
        );
    }

    #[test]
    fn sign_ins_not_enabled_by_entra_id_alone() {
        let content_types = ContentTypesSubConfig {
            general: None,
            azure_active_directory: None,
            exchange: None,
            share_point: None,
            dlp: None,
            ual_graph: None,
            entra_id: Some(true),
            entra_id_sign_ins: None,
            exchange_mailbox_graph: None,
            intune: None,
            identity_protection_risk_detections: None,
        };

        let types = content_types.get_content_type_strings();
        assert!(
            types.contains(&"EntraID.DirectoryAudits".to_string()),
            "directory audits should be enabled"
        );
        assert!(
            !types.contains(&"EntraID.SignIns".to_string()),
            "sign-ins should NOT be enabled without Audit.EntraIDSignIns"
        );
    }

    #[test]
    fn exchange_mailbox_graph_enabled_when_set() {
        let content_types = ContentTypesSubConfig {
            general: None,
            azure_active_directory: None,
            exchange: None,
            share_point: None,
            dlp: None,
            ual_graph: None,
            entra_id: None,
            entra_id_sign_ins: None,
            exchange_mailbox_graph: Some(true),
            intune: None,
            identity_protection_risk_detections: None,
        };

        let types = content_types.get_content_type_strings();
        assert!(
            types.contains(&"ExchangeMailbox.Graph".to_string()),
            "ExchangeMailbox.Graph should be enabled"
        );
        assert_eq!(
            content_types.get_management_content_type_strings().len(),
            0,
            "management API types should be empty"
        );
    }

    #[test]
    fn intune_enabled_when_set() {
        let content_types = ContentTypesSubConfig {
            general: None,
            azure_active_directory: None,
            exchange: None,
            share_point: None,
            dlp: None,
            ual_graph: None,
            entra_id: None,
            entra_id_sign_ins: None,
            exchange_mailbox_graph: None,
            intune: Some(true),
            identity_protection_risk_detections: None,
        };

        let types = content_types.get_content_type_strings();
        assert!(
            types.contains(&"Intune".to_string()),
            "Intune should be enabled"
        );
        assert_eq!(
            content_types.get_management_content_type_strings().len(),
            0,
            "management API types should be empty"
        );
    }

    #[test]
    fn identity_protection_risk_detections_enabled_when_set() {
        let content_types = ContentTypesSubConfig {
            general: None,
            azure_active_directory: None,
            exchange: None,
            share_point: None,
            dlp: None,
            ual_graph: None,
            entra_id: None,
            entra_id_sign_ins: None,
            exchange_mailbox_graph: None,
            intune: None,
            identity_protection_risk_detections: Some(true),
        };

        let types = content_types.get_content_type_strings();
        assert!(
            types.contains(&"IdentityProtection.RiskDetections".to_string()),
            "IdentityProtection.RiskDetections should be enabled"
        );
        assert_eq!(
            content_types.get_management_content_type_strings().len(),
            0,
            "management API types should be empty"
        );
    }
}
