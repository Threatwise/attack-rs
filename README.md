# attack-rs

[![Crates.io](https://img.shields.io/crates/v/attack-rs.svg)](https://crates.io/crates/attack-rs)
[![Documentation](https://docs.rs/attack-rs/badge.svg)](https://docs.rs/attack-rs)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE-MIT)

> **Production-grade Rust library for the MITRE ATT&CK® Framework**

A strongly-typed, high-performance semantic layer for MITRE ATT&CK, providing complete coverage of all ATT&CK objects, relationships, and extended fields. Built on top of [stix-rs](https://github.com/Threatwise/stix-rs) for STIX 2.1 compatibility.

## Features

- **100% ATT&CK Coverage** - All 16 object types, 6 relationship types, 45 extended fields
- **High Performance** - O(1) lookups via HashMap indices, efficient relationship traversal
- **Type-Safe** - Strongly-typed domain models with comprehensive trait implementations
- **Multi-Domain** - Enterprise, Mobile, and ICS ATT&CK matrices
- **Smart Indexing** - T-Code lookup, name search, relationship mapping
- **Validation** - ID validation with revoked/deprecated detection
- **Well-Tested** - 23 comprehensive integration tests

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
attack-rs = "0.1.0"
```

### Basic Usage

```rust
use attack::{AttackStore, AttackObject};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load ATT&CK data
    let store = AttackStore::from_url(
        "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    )?;

    // Query by T-Code
    let technique = store.get_technique_by_tcode("T1566").unwrap();
    println!("Technique: {}", technique.name());
    println!("Platforms: {:?}", technique.platforms);

    // Get related objects
    let groups = store.get_groups_using_technique(technique.id());
    let mitigations = store.get_mitigations_for_technique(technique.id());

    for group in groups {
        println!("Used by: {}", group.name());
    }

    Ok(())
}
```

### Campaign Attribution

```rust
// Track threat campaigns
let campaign = store.get_campaign("campaign--...")?.unwrap();
println!("Campaign: {}", campaign.name());

// Get attribution
let groups = store.get_groups_for_campaign(campaign.id());
let techniques = store.get_techniques_for_campaign(campaign.id());
let software = store.get_software_for_campaign(campaign.id());
```

### Detection Engineering

```rust
// Get granular detection data
let components = store.get_datacomponents_for_technique(tech_id);

for component in components {
    let datasource = store.get_datasource_for_component(component.id()).unwrap();
    println!("Detect via: {} - {}", datasource.name(), component.name());
    // e.g., "Process - Process Creation"
}
```

### Validation

```rust
use attack::{Validator, ValidationResult};

let validator = Validator::new(&store);

match validator.validate_id("attack-pattern--...") {
    ValidationResult::Valid => println!("Valid ATT&CK ID"),
    ValidationResult::Deprecated { replaced_by } => {
        println!("Deprecated, use: {:?}", replaced_by)
    }
    ValidationResult::Revoked { replaced_by } => {
        println!("Revoked, replaced by: {:?}", replaced_by)
    }
    ValidationResult::Unknown => println!("Unknown ID"),
}
```

## Complete ATT&CK Coverage

### Object Types (16/16)

| ATT&CK Object | STIX Type | Description |
|---------------|-----------|-------------|
| **Technique** | `attack-pattern` | Adversary tactics and techniques |
| **Sub-technique** | `attack-pattern` | Specific implementations of techniques |
| **Tactic** | `x-mitre-tactic` | Tactical goals (Initial Access, etc.) |
| **Group** | `intrusion-set` | Threat actor groups (APT29, etc.) |
| **Campaign** | `campaign` | Specific threat operations |
| **Software** | `malware` / `tool` | Malware and tools |
| **Mitigation** | `course-of-action` | Defensive measures |
| **Data Source** | `x-mitre-data-source` | Detection data sources |
| **Data Component** | `x-mitre-data-component` | Granular detection points |
| **Matrix** | `x-mitre-matrix` | Enterprise/Mobile/ICS matrices |
| **Analytic** | `x-mitre-analytic` | Detection analytics |
| **Detection Strategy** | `x-mitre-detection-strategy` | Detection approaches |

### Relationships (6/6)

- `uses` - Group/Campaign → Technique/Software
- `mitigates` - Mitigation → Technique
- `detects` - Data Source/Component → Technique
- `attributed-to` - Campaign → Group
- `subtechnique-of` - Sub-technique → Technique
- `revoked-by` - Old Object → New Object

### Extended Fields (45/45)

All `x_mitre_*` fields are captured, including:
- Version tracking
- Contributors
- Domain classifications
- Detection guidance
- Permission requirements
- Defense bypass methods
- And more...

See the [API Documentation](https://docs.rs/attack-rs) for complete field listings.

## Architecture

```
attack-rs
├── domain/           # Strongly-typed ATT&CK objects
│   ├── technique.rs  # Techniques & sub-techniques
│   ├── tactic.rs     # Tactics
│   ├── group.rs      # Threat actor groups
│   ├── campaign.rs   # Campaigns
│   ├── software.rs   # Malware & tools
│   ├── mitigation.rs # Mitigations
│   ├── data_source.rs      # Data sources
│   ├── data_component.rs   # Data components
│   ├── matrix.rs           # ATT&CK matrices
│   ├── analytic.rs         # Analytics
│   └── detection_strategy.rs
├── store/            # Knowledge graph & indices
├── validation/       # ID validation
└── error/            # Error types
```

## CLI Tool

Install the CLI:

```bash
cargo install attack-rs --features cli
```

### Usage

```bash
# Download ATT&CK data
attack fetch

# Lookup technique
attack lookup T1566
attack lookup phishing

# Validate IDs
attack validate attack-pattern--123 intrusion-set--456

# Display ATT&CK matrix
attack matrix
```

## Testing

Run the test suite:

```bash
cargo test
```

Coverage includes:
- Integration tests (7)
- Full object coverage tests (10)
- Field coverage tests (6)

## Performance

- **Loading**: ~500ms for full Enterprise ATT&CK dataset
- **Memory**: ~20MB for Enterprise ATT&CK (4000+ objects)
- **Lookups**: O(1) via HashMap indices
- **Relationship traversal**: O(k) where k = related objects

## Integration

### With stix-rs

attack-rs is built on [stix-rs](https://github.com/Threatwise/stix-rs):

```rust
use stix_rs::StixObject;
use attack::{AttackStore, Technique};

let tech: Technique = /* ... */;
println!("STIX ID: {}", tech.id());
println!("Created: {}", tech.created());
```

### With hpfeeds-rs

Validate ATT&CK IDs from threat feeds:

```rust
use attack::{AttackStore, Validator};

let store = AttackStore::from_file("enterprise-attack.json")?;
let validator = Validator::new(&store);

// Validate IDs from HPFeeds
if validator.validate_id(threat_id).is_valid() {
    // Process valid ATT&CK reference
}
```

### With maec-rs

Map malware analysis to ATT&CK:

```rust
// Map malware behavior to techniques
let techniques = map_behavior_to_attack(&behavior, &store);
```

## Documentation

- [API Documentation](https://docs.rs/attack-rs) - Complete API reference with examples

## Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure `cargo test` and `cargo clippy` pass
5. Submit a pull request

## License

Licensed under the MIT License. See [LICENSE-MIT](LICENSE-MIT) for details.

## Acknowledgments

- **MITRE Corporation** for the ATT&CK® Framework
- Built for the [Threatwise](https://github.com/Threatwise) threat intelligence stack

---

**MITRE ATT&CK®** is a registered trademark of The MITRE Corporation.
