use attack::{AttackStore, Validator, ValidationResult, AttackObject};
use std::sync::Once;

static INIT: Once = Once::new();

/// Sample minimal ATT&CK bundle for testing
const TEST_BUNDLE: &str = r#"{
  "type": "bundle",
  "id": "bundle--test",
  "objects": [
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
      "x_mitre_platforms": ["Windows", "Linux"],
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
      "x_mitre_platforms": ["Windows", "Linux"],
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
      "name": "Email Logs",
      "description": "Test data source"
    },
    {
      "type": "relationship",
      "id": "relationship--1",
      "created": "2021-01-01T00:00:00.000Z",
      "modified": "2021-01-01T00:00:00.000Z",
      "relationship_type": "uses",
      "source_ref": "intrusion-set--test-group",
      "target_ref": "attack-pattern--test-technique"
    },
    {
      "type": "relationship",
      "id": "relationship--2",
      "created": "2021-01-01T00:00:00.000Z",
      "modified": "2021-01-01T00:00:00.000Z",
      "relationship_type": "mitigates",
      "source_ref": "course-of-action--test-mitigation",
      "target_ref": "attack-pattern--test-technique"
    },
    {
      "type": "relationship",
      "id": "relationship--3",
      "created": "2021-01-01T00:00:00.000Z",
      "modified": "2021-01-01T00:00:00.000Z",
      "relationship_type": "detects",
      "source_ref": "x-mitre-data-source--test-ds",
      "target_ref": "attack-pattern--test-technique"
    }
  ]
}"#;

fn setup_test_bundle() {
    INIT.call_once(|| {
        std::fs::create_dir_all("target/test-data").unwrap();
        std::fs::write("target/test-data/test-bundle.json", TEST_BUNDLE).unwrap();
    });
}

#[test]
fn test_load_bundle() {
    setup_test_bundle();

    let store = AttackStore::from_file("target/test-data/test-bundle.json").unwrap();

    // Verify tactic loaded
    let tactic = store.get_tactic("x-mitre-tactic--test-tactic").unwrap();
    assert_eq!(tactic.name(), "Initial Access");
    assert_eq!(tactic.shortname, "initial-access");

    // Verify technique loaded
    let tech = store.get_technique("attack-pattern--test-technique").unwrap();
    assert_eq!(tech.name(), "Phishing");
    assert_eq!(tech.tcode(), Some("T1566"));
    assert!(!tech.is_subtechnique);

    // Verify sub-technique loaded
    let subtech = store.get_technique("attack-pattern--test-subtechnique").unwrap();
    assert_eq!(subtech.name(), "Spearphishing Link");
    assert_eq!(subtech.tcode(), Some("T1566.001"));
    assert!(subtech.is_subtechnique);

    // Verify group loaded
    let group = store.get_group("intrusion-set--test-group").unwrap();
    assert_eq!(group.name(), "APT1");
}

#[test]
fn test_tcode_lookup() {
    setup_test_bundle();
    let store = AttackStore::from_file("target/test-data/test-bundle.json").unwrap();

    // Test T-Code lookup
    let tech = store.get_technique_by_tcode("T1566").unwrap();
    assert_eq!(tech.name(), "Phishing");

    let subtech = store.get_technique_by_tcode("T1566.001").unwrap();
    assert_eq!(subtech.name(), "Spearphishing Link");

    // Test non-existent T-Code
    assert!(store.get_technique_by_tcode("T9999").is_none());
}

#[test]
fn test_name_lookup() {
    setup_test_bundle();
    let store = AttackStore::from_file("target/test-data/test-bundle.json").unwrap();

    // Test name-based search
    let tech = store.find_technique_by_name("phishing").unwrap();
    assert_eq!(tech.tcode(), Some("T1566"));

    let tech2 = store.find_technique_by_name("PHISHING").unwrap();
    assert_eq!(tech2.tcode(), Some("T1566"));

    // Partial match
    let tech3 = store.find_technique_by_name("spear").unwrap();
    assert_eq!(tech3.tcode(), Some("T1566.001"));
}

#[test]
fn test_relationships() {
    setup_test_bundle();
    let store = AttackStore::from_file("target/test-data/test-bundle.json").unwrap();

    let tech_id = "attack-pattern--test-technique";

    // Test group relationships
    let groups = store.get_groups_using_technique(tech_id);
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].name(), "APT1");

    // Test mitigation relationships
    let mitigations = store.get_mitigations_for_technique(tech_id);
    assert_eq!(mitigations.len(), 1);
    assert_eq!(mitigations[0].name(), "User Training");

    // Test data source relationships
    let datasources = store.get_datasources_for_technique(tech_id);
    assert_eq!(datasources.len(), 1);
    assert_eq!(datasources[0].name(), "Email Logs");
}

#[test]
fn test_subtechnique_hierarchy() {
    setup_test_bundle();
    let store = AttackStore::from_file("target/test-data/test-bundle.json").unwrap();

    // Test parent lookup from subtechnique
    let parent = store.get_parent_technique("attack-pattern--test-subtechnique").unwrap();
    assert_eq!(parent.tcode(), Some("T1566"));
    assert_eq!(parent.name(), "Phishing");

    // Test subtechnique lookup from parent
    let subtechs = store.get_subtechniques("attack-pattern--test-technique");
    assert_eq!(subtechs.len(), 1);
    assert_eq!(subtechs[0].tcode(), Some("T1566.001"));
}

#[test]
fn test_validation() {
    setup_test_bundle();
    let store = AttackStore::from_file("target/test-data/test-bundle.json").unwrap();
    let validator = Validator::new(&store);

    // Valid ID
    let result = validator.validate_id("attack-pattern--test-technique");
    assert_eq!(result, ValidationResult::Valid);

    // Unknown ID
    let result = validator.validate_id("attack-pattern--nonexistent");
    assert_eq!(result, ValidationResult::Unknown);
}

#[test]
fn test_iterators() {
    setup_test_bundle();
    let store = AttackStore::from_file("target/test-data/test-bundle.json").unwrap();

    // Test all iterators work
    assert_eq!(store.tactics().count(), 1);
    assert_eq!(store.techniques().count(), 2);
    assert_eq!(store.groups().count(), 1);
    assert_eq!(store.software().count(), 1);
    assert_eq!(store.mitigations().count(), 1);
    assert_eq!(store.data_sources().count(), 1);
}
