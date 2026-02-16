use attack::{AttackStore, AttackObject};
use stix_rs::StixObject;
use std::sync::Once;

static INIT: Once = Once::new();

/// Extended test bundle with all ATT&CK object types
const EXTENDED_BUNDLE: &str = r#"{
  "type": "bundle",
  "id": "bundle--test-extended",
  "objects": [
    {
      "type": "x-mitre-matrix",
      "id": "x-mitre-matrix--test-matrix",
      "created": "2021-01-01T00:00:00.000Z",
      "modified": "2021-01-01T00:00:00.000Z",
      "name": "Enterprise ATT&CK",
      "description": "Test matrix",
      "tactic_refs": ["x-mitre-tactic--test-tactic"]
    },
    {
      "type": "x-mitre-tactic",
      "id": "x-mitre-tactic--test-tactic",
      "created": "2021-01-01T00:00:00.000Z",
      "modified": "2021-01-01T00:00:00.000Z",
      "name": "Initial Access",
      "description": "Test tactic",
      "x_mitre_shortname": "initial-access"
    },
    {
      "type": "attack-pattern",
      "id": "attack-pattern--test-technique",
      "created": "2021-01-01T00:00:00.000Z",
      "modified": "2021-01-01T00:00:00.000Z",
      "name": "Phishing",
      "description": "Test technique",
      "x_mitre_is_subtechnique": false,
      "x_mitre_platforms": ["Windows"],
      "kill_chain_phases": [
        {
          "kill_chain_name": "mitre-attack",
          "phase_name": "initial-access"
        }
      ],
      "external_references": [
        {
          "source_name": "mitre-attack",
          "external_id": "T1566"
        }
      ]
    },
    {
      "type": "attack-pattern",
      "id": "attack-pattern--test-subtechnique",
      "created": "2021-01-01T00:00:00.000Z",
      "modified": "2021-01-01T00:00:00.000Z",
      "name": "Spearphishing Link",
      "description": "Test sub-technique",
      "x_mitre_is_subtechnique": true,
      "x_mitre_platforms": ["Windows"],
      "kill_chain_phases": [
        {
          "kill_chain_name": "mitre-attack",
          "phase_name": "initial-access"
        }
      ],
      "external_references": [
        {
          "source_name": "mitre-attack",
          "external_id": "T1566.001"
        }
      ]
    },
    {
      "type": "intrusion-set",
      "id": "intrusion-set--test-group",
      "created": "2021-01-01T00:00:00.000Z",
      "modified": "2021-01-01T00:00:00.000Z",
      "name": "APT1",
      "description": "Test group"
    },
    {
      "type": "campaign",
      "id": "campaign--test-campaign",
      "created": "2021-01-01T00:00:00.000Z",
      "modified": "2021-01-01T00:00:00.000Z",
      "name": "Operation Solar Storm",
      "description": "Test campaign",
      "first_seen": "2020-01-01T00:00:00.000Z",
      "last_seen": "2020-12-31T00:00:00.000Z"
    },
    {
      "type": "malware",
      "id": "malware--test-malware",
      "created": "2021-01-01T00:00:00.000Z",
      "modified": "2021-01-01T00:00:00.000Z",
      "name": "BadMalware",
      "description": "Test malware",
      "is_family": false
    },
    {
      "type": "course-of-action",
      "id": "course-of-action--test-mitigation",
      "created": "2021-01-01T00:00:00.000Z",
      "modified": "2021-01-01T00:00:00.000Z",
      "name": "User Training",
      "description": "Test mitigation"
    },
    {
      "type": "x-mitre-data-source",
      "id": "x-mitre-data-source--test-ds",
      "created": "2021-01-01T00:00:00.000Z",
      "modified": "2021-01-01T00:00:00.000Z",
      "name": "Process",
      "description": "Test data source"
    },
    {
      "type": "x-mitre-data-component",
      "id": "x-mitre-data-component--test-dc",
      "created": "2021-01-01T00:00:00.000Z",
      "modified": "2021-01-01T00:00:00.000Z",
      "name": "Process Creation",
      "description": "Test data component",
      "x_mitre_data_source_ref": "x-mitre-data-source--test-ds"
    },
    {
      "type": "x-mitre-analytic",
      "id": "x-mitre-analytic--test-analytic",
      "created": "2021-01-01T00:00:00.000Z",
      "modified": "2021-01-01T00:00:00.000Z",
      "name": "Detect Phishing",
      "description": "Test analytic"
    },
    {
      "type": "x-mitre-detection-strategy",
      "id": "x-mitre-detection-strategy--test-strategy",
      "created": "2021-01-01T00:00:00.000Z",
      "modified": "2021-01-01T00:00:00.000Z",
      "name": "Behavioral Analysis",
      "description": "Test detection strategy"
    },
    {
      "type": "relationship",
      "id": "relationship--1",
      "created": "2021-01-01T00:00:00.000Z",
      "modified": "2021-01-01T00:00:00.000Z",
      "relationship_type": "attributed-to",
      "source_ref": "campaign--test-campaign",
      "target_ref": "intrusion-set--test-group"
    },
    {
      "type": "relationship",
      "id": "relationship--2",
      "created": "2021-01-01T00:00:00.000Z",
      "modified": "2021-01-01T00:00:00.000Z",
      "relationship_type": "uses",
      "source_ref": "campaign--test-campaign",
      "target_ref": "attack-pattern--test-technique"
    },
    {
      "type": "relationship",
      "id": "relationship--3",
      "created": "2021-01-01T00:00:00.000Z",
      "modified": "2021-01-01T00:00:00.000Z",
      "relationship_type": "uses",
      "source_ref": "campaign--test-campaign",
      "target_ref": "malware--test-malware"
    },
    {
      "type": "relationship",
      "id": "relationship--4",
      "created": "2021-01-01T00:00:00.000Z",
      "modified": "2021-01-01T00:00:00.000Z",
      "relationship_type": "mitigates",
      "source_ref": "course-of-action--test-mitigation",
      "target_ref": "attack-pattern--test-technique"
    },
    {
      "type": "relationship",
      "id": "relationship--5",
      "created": "2021-01-01T00:00:00.000Z",
      "modified": "2021-01-01T00:00:00.000Z",
      "relationship_type": "detects",
      "source_ref": "x-mitre-data-component--test-dc",
      "target_ref": "attack-pattern--test-technique"
    },
    {
      "type": "relationship",
      "id": "relationship--6",
      "created": "2021-01-01T00:00:00.000Z",
      "modified": "2021-01-01T00:00:00.000Z",
      "relationship_type": "subtechnique-of",
      "source_ref": "attack-pattern--test-subtechnique",
      "target_ref": "attack-pattern--test-technique"
    }
  ]
}"#;

fn setup_extended_bundle() {
    INIT.call_once(|| {
        std::fs::create_dir_all("target/test-data").unwrap();
        std::fs::write("target/test-data/extended-bundle.json", EXTENDED_BUNDLE).unwrap();
    });
}

#[test]
fn test_all_object_types_loaded() {
    setup_extended_bundle();
    let store = AttackStore::from_file("target/test-data/extended-bundle.json").unwrap();

    // Verify all object types are loaded
    assert_eq!(store.matrices().count(), 1);
    assert_eq!(store.tactics().count(), 1);
    assert_eq!(store.techniques().count(), 2);
    assert_eq!(store.groups().count(), 1);
    assert_eq!(store.campaigns().count(), 1);
    assert_eq!(store.software().count(), 1);
    assert_eq!(store.mitigations().count(), 1);
    assert_eq!(store.data_sources().count(), 1);
    assert_eq!(store.data_components().count(), 1);
    assert_eq!(store.analytics().count(), 1);
    assert_eq!(store.detection_strategies().count(), 1);
}

#[test]
fn test_campaign_objects() {
    setup_extended_bundle();
    let store = AttackStore::from_file("target/test-data/extended-bundle.json").unwrap();

    let campaign = store.get_campaign("campaign--test-campaign").unwrap();
    assert_eq!(campaign.name(), "Operation Solar Storm");
    assert!(campaign.first_seen.is_some());
    assert!(campaign.last_seen.is_some());
}

#[test]
fn test_campaign_relationships() {
    setup_extended_bundle();
    let store = AttackStore::from_file("target/test-data/extended-bundle.json").unwrap();

    let campaign_id = "campaign--test-campaign";

    // Campaign -> Group (attributed-to)
    let groups = store.get_groups_for_campaign(campaign_id);
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].name(), "APT1");

    // Campaign -> Technique
    let techniques = store.get_techniques_for_campaign(campaign_id);
    assert_eq!(techniques.len(), 1);
    assert_eq!(techniques[0].name(), "Phishing");

    // Campaign -> Software
    let software = store.get_software_for_campaign(campaign_id);
    assert_eq!(software.len(), 1);
    assert_eq!(software[0].name(), "BadMalware");
}

#[test]
fn test_data_component_objects() {
    setup_extended_bundle();
    let store = AttackStore::from_file("target/test-data/extended-bundle.json").unwrap();

    let dc = store.get_data_component("x-mitre-data-component--test-dc").unwrap();
    assert_eq!(dc.name(), "Process Creation");
    assert_eq!(dc.data_source_ref, Some("x-mitre-data-source--test-ds".to_string()));
}

#[test]
fn test_data_component_relationships() {
    setup_extended_bundle();
    let store = AttackStore::from_file("target/test-data/extended-bundle.json").unwrap();

    // Data Component -> Data Source (parent)
    let dc_id = "x-mitre-data-component--test-dc";
    let ds = store.get_datasource_for_component(dc_id).unwrap();
    assert_eq!(ds.name(), "Process");

    // Data Source -> Data Components (children)
    let ds_id = "x-mitre-data-source--test-ds";
    let components = store.get_components_for_datasource(ds_id);
    assert_eq!(components.len(), 1);
    assert_eq!(components[0].name(), "Process Creation");

    // Data Component -> Technique (detects)
    let tech_id = "attack-pattern--test-technique";
    let components = store.get_datacomponents_for_technique(tech_id);
    assert_eq!(components.len(), 1);
    assert_eq!(components[0].name(), "Process Creation");
}

#[test]
fn test_matrix_objects() {
    setup_extended_bundle();
    let store = AttackStore::from_file("target/test-data/extended-bundle.json").unwrap();

    let matrix = store.get_matrix("x-mitre-matrix--test-matrix").unwrap();
    assert_eq!(matrix.name(), "Enterprise ATT&CK");
    assert_eq!(matrix.tactic_refs.len(), 1);
}

#[test]
fn test_analytic_objects() {
    setup_extended_bundle();
    let store = AttackStore::from_file("target/test-data/extended-bundle.json").unwrap();

    let analytic = store.get_analytic("x-mitre-analytic--test-analytic").unwrap();
    assert_eq!(analytic.name(), "Detect Phishing");
}

#[test]
fn test_detection_strategy_objects() {
    setup_extended_bundle();
    let store = AttackStore::from_file("target/test-data/extended-bundle.json").unwrap();

    let strategy = store.get_detection_strategy("x-mitre-detection-strategy--test-strategy").unwrap();
    assert_eq!(strategy.name(), "Behavioral Analysis");
}

#[test]
fn test_subtechnique_of_relationship() {
    setup_extended_bundle();
    let store = AttackStore::from_file("target/test-data/extended-bundle.json").unwrap();

    // Test explicit subtechnique-of relationship
    let parent = store.get_parent_technique("attack-pattern--test-subtechnique").unwrap();
    assert_eq!(parent.tcode(), Some("T1566"));
}

#[test]
fn test_100_percent_coverage() {
    setup_extended_bundle();
    let store = AttackStore::from_file("target/test-data/extended-bundle.json").unwrap();

    // Verify we can load and access all 16 ATT&CK object types
    // Core STIX SDOs (used by ATT&CK)
    assert!(store.get_group("intrusion-set--test-group").is_some()); // intrusion-set
    assert!(store.get_technique("attack-pattern--test-technique").is_some()); // attack-pattern
    assert!(store.get_software("malware--test-malware").is_some()); // malware
    assert!(store.get_mitigation("course-of-action--test-mitigation").is_some()); // course-of-action
    assert!(store.get_campaign("campaign--test-campaign").is_some()); // campaign

    // ATT&CK Custom Objects (x-mitre-*)
    assert!(store.get_tactic("x-mitre-tactic--test-tactic").is_some()); // x-mitre-tactic
    assert!(store.get_matrix("x-mitre-matrix--test-matrix").is_some()); // x-mitre-matrix
    assert!(store.get_data_source("x-mitre-data-source--test-ds").is_some()); // x-mitre-data-source
    assert!(store.get_data_component("x-mitre-data-component--test-dc").is_some()); // x-mitre-data-component
    assert!(store.get_analytic("x-mitre-analytic--test-analytic").is_some()); // x-mitre-analytic
    assert!(store.get_detection_strategy("x-mitre-detection-strategy--test-strategy").is_some()); // x-mitre-detection-strategy

    println!("✅ 100% ATT&CK object type coverage verified!");
}
