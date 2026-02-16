use serde::{Deserialize, Serialize};
use stix_rs::{CommonProperties, StixObject};
use crate::domain::AttackObject;

/// Represents MITRE ATT&CK Malware.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Malware {
    #[serde(flatten)]
    pub common: CommonProperties,
    pub name: String,
    pub description: Option<String>,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default, rename = "x_mitre_platforms")]
    pub platforms: Vec<String>,
    #[serde(default)]
    pub is_family: bool,

    // Extended ATT&CK fields
    #[serde(default, rename = "x_mitre_version")]
    pub version: Option<String>,

    #[serde(default, rename = "x_mitre_contributors")]
    pub contributors: Vec<String>,

    #[serde(default, rename = "x_mitre_domains")]
    pub domains: Vec<String>,

    #[serde(default, rename = "x_mitre_aliases")]
    pub mitre_aliases: Vec<String>,
}

/// Represents MITRE ATT&CK Tool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tool {
    #[serde(flatten)]
    pub common: CommonProperties,
    pub name: String,
    pub description: Option<String>,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default, rename = "x_mitre_platforms")]
    pub platforms: Vec<String>,

    // Extended ATT&CK fields
    #[serde(default, rename = "x_mitre_version")]
    pub version: Option<String>,

    #[serde(default, rename = "x_mitre_contributors")]
    pub contributors: Vec<String>,

    #[serde(default, rename = "x_mitre_domains")]
    pub domains: Vec<String>,

    #[serde(default, rename = "x_mitre_aliases")]
    pub mitre_aliases: Vec<String>,
}

/// Combined type for software (either malware or tool).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Software {
    Malware(Malware),
    Tool(Tool),
}

impl StixObject for Malware {
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

impl AttackObject for Malware {
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

impl StixObject for Tool {
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

impl AttackObject for Tool {
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

impl StixObject for Software {
    fn id(&self) -> &str {
        match self {
            Software::Malware(m) => m.id(),
            Software::Tool(t) => t.id(),
        }
    }

    fn type_(&self) -> &str {
        match self {
            Software::Malware(m) => m.type_(),
            Software::Tool(t) => t.type_(),
        }
    }

    fn created(&self) -> chrono::DateTime<chrono::Utc> {
        match self {
            Software::Malware(m) => m.created(),
            Software::Tool(t) => t.created(),
        }
    }
}

impl AttackObject for Software {
    fn name(&self) -> &str {
        match self {
            Software::Malware(m) => m.name(),
            Software::Tool(t) => t.name(),
        }
    }

    fn description(&self) -> Option<&str> {
        match self {
            Software::Malware(m) => m.description(),
            Software::Tool(t) => t.description(),
        }
    }

    fn revoked(&self) -> bool {
        match self {
            Software::Malware(m) => m.revoked(),
            Software::Tool(t) => t.revoked(),
        }
    }

    fn deprecated(&self) -> bool {
        match self {
            Software::Malware(m) => m.deprecated(),
            Software::Tool(t) => t.deprecated(),
        }
    }
}
