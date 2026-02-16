use serde::{Deserialize, Serialize};
use stix_rs::{CommonProperties, StixObject, KillChainPhase};
use crate::domain::AttackObject;

/// Represents a MITRE ATT&CK Technique (attack-pattern).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Technique {
    #[serde(flatten)]
    pub common: CommonProperties,

    pub name: String,
    pub description: Option<String>,

    #[serde(default, rename = "x_mitre_is_subtechnique")]
    pub is_subtechnique: bool,

    #[serde(default, rename = "x_mitre_platforms")]
    pub platforms: Vec<String>,

    #[serde(default)]
    pub kill_chain_phases: Vec<KillChainPhase>,

    // Extended ATT&CK fields
    #[serde(default, rename = "x_mitre_version")]
    pub version: Option<String>,

    #[serde(default, rename = "x_mitre_detection")]
    pub detection: Option<String>,

    #[serde(default, rename = "x_mitre_permissions_required")]
    pub permissions_required: Vec<String>,

    #[serde(default, rename = "x_mitre_effective_permissions")]
    pub effective_permissions: Vec<String>,

    #[serde(default, rename = "x_mitre_defense_bypassed")]
    pub defense_bypassed: Vec<String>,

    #[serde(default, rename = "x_mitre_system_requirements")]
    pub system_requirements: Vec<String>,

    #[serde(default, rename = "x_mitre_network_requirements")]
    pub network_requirements: Option<bool>,

    #[serde(default, rename = "x_mitre_remote_support")]
    pub remote_support: Option<bool>,

    #[serde(default, rename = "x_mitre_data_sources")]
    pub data_sources_legacy: Vec<String>,

    #[serde(default, rename = "x_mitre_impact_type")]
    pub impact_type: Vec<String>,

    #[serde(default, rename = "x_mitre_contributors")]
    pub contributors: Vec<String>,

    #[serde(default, rename = "x_mitre_domains")]
    pub domains: Vec<String>,
}

impl Technique {
    /// Extracts the ATT&CK T-Code (e.g., "T1566" or "T1566.001") from external references.
    pub fn tcode(&self) -> Option<&str> {
        self.common.external_references.as_ref()?
            .iter()
            .find(|r| r.source_name == "mitre-attack" || r.source_name == "mitre-mobile-attack" || r.source_name == "mitre-ics-attack")?
            .external_id.as_deref()
    }

    /// Gets the tactics this technique belongs to from kill chain phases.
    pub fn tactics(&self) -> Vec<&str> {
        self.kill_chain_phases.iter()
            .filter(|phase| phase.name == "mitre-attack" || phase.name == "mitre-mobile-attack" || phase.name == "mitre-ics-attack")
            .map(|phase| phase.phase_name.as_str())
            .collect()
    }
}

impl StixObject for Technique {
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

impl AttackObject for Technique {
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
