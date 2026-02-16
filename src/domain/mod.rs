use stix_rs::StixObject;

/// Base trait for all MITRE ATT&CK objects.
/// Extends the basic STIX object with ATT&CK-specific common fields.
pub trait AttackObject: StixObject {
    fn name(&self) -> &str;
    fn description(&self) -> Option<&str>;
    fn revoked(&self) -> bool;
    fn deprecated(&self) -> bool;
}

pub mod tactic;
pub mod technique;
pub mod group;
pub mod software;
pub mod mitigation;
pub mod data_source;
pub mod data_component;
pub mod campaign;
pub mod matrix;
pub mod analytic;
pub mod detection_strategy;

pub use tactic::Tactic;
pub use technique::Technique;
pub use group::Group;
pub use software::{Software, Malware, Tool};
pub use mitigation::Mitigation;
pub use data_source::DataSource;
pub use data_component::DataComponent;
pub use campaign::Campaign;
pub use matrix::Matrix;
pub use analytic::Analytic;
pub use detection_strategy::DetectionStrategy;
