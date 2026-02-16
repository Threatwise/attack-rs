use serde::{Deserialize, Serialize};
use stix_rs::{CommonProperties, StixObject};
use crate::domain::AttackObject;

/// Represents a MITRE ATT&CK Detection Strategy (x-mitre-detection-strategy).
///
/// Detection strategies describe high-level approaches to detecting
/// adversary behavior.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectionStrategy {
    #[serde(flatten)]
    pub common: CommonProperties,

    pub name: String,
    pub description: Option<String>,

    // Extended ATT&CK fields
    #[serde(default, rename = "x_mitre_version")]
    pub version: Option<String>,

    #[serde(default, rename = "x_mitre_domains")]
    pub domains: Vec<String>,
}

impl StixObject for DetectionStrategy {
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

impl AttackObject for DetectionStrategy {
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
