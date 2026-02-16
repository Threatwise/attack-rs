use serde::{Deserialize, Serialize};
use stix_rs::{CommonProperties, StixObject};
use crate::domain::AttackObject;

/// Represents a MITRE ATT&CK Data Component (x-mitre-data-component).
///
/// Data Components are specific properties or values of a Data Source that
/// can be used to detect adversary behavior. For example, the "Process" data
/// source has components like "Process Creation", "Process Termination", etc.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataComponent {
    #[serde(flatten)]
    pub common: CommonProperties,

    pub name: String,
    pub description: Option<String>,

    /// Reference to parent Data Source
    #[serde(rename = "x_mitre_data_source_ref")]
    pub data_source_ref: Option<String>,

    // Extended ATT&CK fields
    #[serde(default, rename = "x_mitre_version")]
    pub version: Option<String>,

    #[serde(default, rename = "x_mitre_domains")]
    pub domains: Vec<String>,
}

impl StixObject for DataComponent {
    fn id(&self) -> &str {
        &self.common.id
    }

    fn type_(&self) -> &str {
        &self.common.r#type
    }

    fn created(&self) -> chrono::DateTime<chrono::Utc> {
        self.common.created
    }
}

impl AttackObject for DataComponent {
    fn name(&self) -> &str {
        &self.name
    }

    fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    fn revoked(&self) -> bool {
        self.common.revoked.unwrap_or(false)
    }

    fn deprecated(&self) -> bool {
        self.common.custom_properties.get("x_mitre_deprecated").and_then(|v| v.as_bool()).unwrap_or(false)
    }
}
