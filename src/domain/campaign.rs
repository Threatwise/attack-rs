use serde::{Deserialize, Serialize};
use stix_rs::{CommonProperties, StixObject};
use crate::domain::AttackObject;
use chrono::{DateTime, Utc};

/// Represents a MITRE ATT&CK Campaign.
///
/// Campaigns represent groupings of adversarial behaviors that describe a set of
/// malicious activities or attacks that occur over a period of time against a
/// specific set of targets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Campaign {
    #[serde(flatten)]
    pub common: CommonProperties,

    pub name: String,
    pub description: Option<String>,

    #[serde(default)]
    pub aliases: Vec<String>,

    pub first_seen: Option<DateTime<Utc>>,
    pub last_seen: Option<DateTime<Utc>>,

    #[serde(default)]
    pub objective: Option<String>,

    // Extended ATT&CK fields
    #[serde(default, rename = "x_mitre_version")]
    pub version: Option<String>,

    #[serde(default, rename = "x_mitre_contributors")]
    pub contributors: Vec<String>,

    #[serde(default, rename = "x_mitre_first_seen_citation")]
    pub first_seen_citation: Option<String>,

    #[serde(default, rename = "x_mitre_last_seen_citation")]
    pub last_seen_citation: Option<String>,

    #[serde(default, rename = "x_mitre_domains")]
    pub domains: Vec<String>,
}

impl StixObject for Campaign {
    fn id(&self) -> &str {
        &self.common.id
    }

    fn type_(&self) -> &str {
        &self.common.r#type
    }

    fn created(&self) -> DateTime<Utc> {
        self.common.created
    }
}

impl AttackObject for Campaign {
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
