//! attack-rs: MITRE ATT&CK Framework semantic layer
//!
//! Provides strongly-typed, graph-based interface to the MITRE ATT&CK dataset.
//! Built on top of stix-rs for parsing ATT&CK STIX bundles.

pub mod domain;
pub mod error;
pub mod store;
pub mod validation;

pub use domain::*;
pub use error::*;
pub use store::*;
pub use validation::*;
