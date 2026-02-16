use std::collections::HashMap;
use std::path::Path;
use serde::Deserialize;
use crate::domain::{*, software};
use crate::error::Result;
use stix_rs::{Relationship, StixObject};

#[derive(Debug, Default)]
pub struct AttackStore {
    tactics: HashMap<String, Tactic>,
    techniques: HashMap<String, Technique>,
    groups: HashMap<String, Group>,
    software: HashMap<String, Software>,
    mitigations: HashMap<String, Mitigation>,
    data_sources: HashMap<String, DataSource>,
    data_components: HashMap<String, DataComponent>,
    campaigns: HashMap<String, Campaign>,
    matrices: HashMap<String, Matrix>,
    analytics: HashMap<String, Analytic>,
    detection_strategies: HashMap<String, DetectionStrategy>,

    // Secondary Indices
    tcode_index: HashMap<String, String>, // T-Code -> ID
    technique_to_group: HashMap<String, Vec<String>>,
    software_to_group: HashMap<String, Vec<String>>,
    technique_to_mitigation: HashMap<String, Vec<String>>,
    technique_to_datasource: HashMap<String, Vec<String>>,
    technique_to_datacomponent: HashMap<String, Vec<String>>,
    subtechnique_to_technique: HashMap<String, String>,
    campaign_to_group: HashMap<String, Vec<String>>,
    campaign_to_technique: HashMap<String, Vec<String>>,
    campaign_to_software: HashMap<String, Vec<String>>,
    datacomponent_to_datasource: HashMap<String, String>,

    // Replacement Index (source_ref -> target_ref where type is revoked-by)
    replacements: HashMap<String, String>,
}

#[derive(Deserialize)]
struct StixBundle {
    objects: Vec<serde_json::Value>,
}

impl AttackStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = std::fs::File::open(path)?;
        let bundle: StixBundle = serde_json::from_reader(file)?;
        Ok(Self::from_bundle(bundle))
    }

    pub fn from_url(url: &str) -> Result<Self> {
        let resp = reqwest::blocking::get(url)?;
        let bundle: StixBundle = resp.json()?;
        Ok(Self::from_bundle(bundle))
    }

    fn from_bundle(bundle: StixBundle) -> Self {
        let mut store = Self::new();
        let mut relationships = Vec::new();

        for obj in bundle.objects {
            let type_ = obj.get("type").and_then(|v| v.as_str()).unwrap_or("");
            match type_ {
                "x-mitre-tactic" => {
                    if let Ok(tactic) = serde_json::from_value::<Tactic>(obj) {
                        store.tactics.insert(tactic.id().to_string(), tactic);
                    }
                }
                "attack-pattern" => {
                    if let Ok(technique) = serde_json::from_value::<Technique>(obj) {
                        if let Some(tcode) = technique.tcode() {
                            store.tcode_index.insert(tcode.to_string(), technique.id().to_string());
                        }
                        store.techniques.insert(technique.id().to_string(), technique);
                    }
                }
                "intrusion-set" => {
                    if let Ok(group) = serde_json::from_value::<Group>(obj) {
                        store.groups.insert(group.id().to_string(), group);
                    }
                }
                "malware" => {
                    if let Ok(malware) = serde_json::from_value::<software::Malware>(obj) {
                        let id = malware.id().to_string();
                        store.software.insert(id, Software::Malware(malware));
                    }
                }
                "tool" => {
                    if let Ok(tool) = serde_json::from_value::<software::Tool>(obj) {
                        let id = tool.id().to_string();
                        store.software.insert(id, Software::Tool(tool));
                    }
                }
                "course-of-action" => {
                    if let Ok(mitigation) = serde_json::from_value::<Mitigation>(obj) {
                        store.mitigations.insert(mitigation.id().to_string(), mitigation);
                    }
                }
                "x-mitre-data-source" => {
                    if let Ok(ds) = serde_json::from_value::<DataSource>(obj) {
                        store.data_sources.insert(ds.id().to_string(), ds);
                    }
                }
                "x-mitre-data-component" => {
                    if let Ok(dc) = serde_json::from_value::<DataComponent>(obj.clone()) {
                        // Store data component to data source mapping
                        if let Some(ds_ref) = &dc.data_source_ref {
                            store.datacomponent_to_datasource.insert(dc.id().to_string(), ds_ref.clone());
                        }
                        store.data_components.insert(dc.id().to_string(), dc);
                    }
                }
                "campaign" => {
                    if let Ok(campaign) = serde_json::from_value::<Campaign>(obj) {
                        store.campaigns.insert(campaign.id().to_string(), campaign);
                    }
                }
                "x-mitre-matrix" => {
                    if let Ok(matrix) = serde_json::from_value::<Matrix>(obj) {
                        store.matrices.insert(matrix.id().to_string(), matrix);
                    }
                }
                "x-mitre-analytic" => {
                    if let Ok(analytic) = serde_json::from_value::<Analytic>(obj) {
                        store.analytics.insert(analytic.id().to_string(), analytic);
                    }
                }
                "x-mitre-detection-strategy" => {
                    if let Ok(strategy) = serde_json::from_value::<DetectionStrategy>(obj) {
                        store.detection_strategies.insert(strategy.id().to_string(), strategy);
                    }
                }
                "relationship" => {
                    if let Ok(rel) = serde_json::from_value::<Relationship>(obj) {
                        relationships.push(rel);
                    }
                }
                _ => {}
            }
        }

        // Process relationships and build parent-child hierarchy
        for tech in store.techniques.values() {
            if tech.is_subtechnique {
                // Extract parent from T-Code (e.g., T1566.001 -> T1566)
                if let Some(tcode) = tech.tcode()
                    && let Some(parent_tcode) = tcode.split('.').next()
                    && let Some(parent_id) = store.tcode_index.get(parent_tcode)
                {
                    store.subtechnique_to_technique.insert(tech.id().to_string(), parent_id.clone());
                }
            }
        }

        // Process relationships
        for rel in relationships {
            match rel.relationship_type.as_str() {
                "uses" => {
                    // Group/Campaign -> Technique
                    if rel.target_ref.starts_with("attack-pattern--") {
                        if rel.source_ref.starts_with("intrusion-set--") {
                            store.technique_to_group.entry(rel.target_ref.clone()).or_default().push(rel.source_ref.clone());
                        } else if rel.source_ref.starts_with("campaign--") {
                            store.campaign_to_technique.entry(rel.source_ref.clone()).or_default().push(rel.target_ref.clone());
                        }
                    }
                    // Group/Campaign -> Software
                    else if rel.target_ref.starts_with("malware--") || rel.target_ref.starts_with("tool--") {
                        if rel.source_ref.starts_with("intrusion-set--") {
                            store.software_to_group.entry(rel.target_ref.clone()).or_default().push(rel.source_ref.clone());
                        } else if rel.source_ref.starts_with("campaign--") {
                            store.campaign_to_software.entry(rel.source_ref.clone()).or_default().push(rel.target_ref.clone());
                        }
                    }
                }
                "mitigates" => {
                    if rel.target_ref.starts_with("attack-pattern--") && rel.source_ref.starts_with("course-of-action--") {
                        store.technique_to_mitigation.entry(rel.target_ref.clone()).or_default().push(rel.source_ref.clone());
                    }
                }
                "detects" => {
                    if rel.target_ref.starts_with("attack-pattern--") {
                        if rel.source_ref.starts_with("x-mitre-data-source--") {
                            store.technique_to_datasource.entry(rel.target_ref.clone()).or_default().push(rel.source_ref.clone());
                        } else if rel.source_ref.starts_with("x-mitre-data-component--") {
                            store.technique_to_datacomponent.entry(rel.target_ref.clone()).or_default().push(rel.source_ref.clone());
                        }
                    }
                }
                "attributed-to" => {
                    if rel.source_ref.starts_with("campaign--") && rel.target_ref.starts_with("intrusion-set--") {
                        store.campaign_to_group.entry(rel.source_ref.clone()).or_default().push(rel.target_ref.clone());
                    }
                }
                "subtechnique-of" => {
                    if rel.source_ref.starts_with("attack-pattern--") && rel.target_ref.starts_with("attack-pattern--") {
                        store.subtechnique_to_technique.insert(rel.source_ref.clone(), rel.target_ref.clone());
                    }
                }
                "revoked-by" => {
                    store.replacements.insert(rel.source_ref.clone(), rel.target_ref.clone());
                }
                _ => {}
            }
        }

        store
    }

    pub fn get_tactic(&self, id: &str) -> Option<&Tactic> { self.tactics.get(id) }
    pub fn get_technique(&self, id: &str) -> Option<&Technique> { self.techniques.get(id) }
    pub fn get_group(&self, id: &str) -> Option<&Group> { self.groups.get(id) }
    pub fn get_software(&self, id: &str) -> Option<&Software> { self.software.get(id) }
    pub fn get_mitigation(&self, id: &str) -> Option<&Mitigation> { self.mitigations.get(id) }
    pub fn get_data_source(&self, id: &str) -> Option<&DataSource> { self.data_sources.get(id) }
    pub fn get_data_component(&self, id: &str) -> Option<&DataComponent> { self.data_components.get(id) }
    pub fn get_campaign(&self, id: &str) -> Option<&Campaign> { self.campaigns.get(id) }
    pub fn get_matrix(&self, id: &str) -> Option<&Matrix> { self.matrices.get(id) }
    pub fn get_analytic(&self, id: &str) -> Option<&Analytic> { self.analytics.get(id) }
    pub fn get_detection_strategy(&self, id: &str) -> Option<&DetectionStrategy> { self.detection_strategies.get(id) }

    pub fn get_replacement(&self, id: &str) -> Option<&str> {
        self.replacements.get(id).map(|s| s.as_str())
    }

    pub fn get_technique_by_tcode(&self, tcode: &str) -> Option<&Technique> {
        let id = self.tcode_index.get(tcode)?;
        self.techniques.get(id)
    }

    pub fn get_groups_using_technique(&self, technique_id: &str) -> Vec<&Group> {
        self.technique_to_group.get(technique_id)
            .map(|ids| ids.iter().filter_map(|id| self.get_group(id)).collect())
            .unwrap_or_default()
    }

    pub fn get_mitigations_for_technique(&self, technique_id: &str) -> Vec<&Mitigation> {
        self.technique_to_mitigation.get(technique_id)
            .map(|ids| ids.iter().filter_map(|id| self.get_mitigation(id)).collect())
            .unwrap_or_default()
    }

    pub fn get_datasources_for_technique(&self, technique_id: &str) -> Vec<&DataSource> {
        self.technique_to_datasource.get(technique_id)
            .map(|ids| ids.iter().filter_map(|id| self.get_data_source(id)).collect())
            .unwrap_or_default()
    }

    pub fn get_datacomponents_for_technique(&self, technique_id: &str) -> Vec<&DataComponent> {
        self.technique_to_datacomponent.get(technique_id)
            .map(|ids| ids.iter().filter_map(|id| self.get_data_component(id)).collect())
            .unwrap_or_default()
    }

    pub fn get_datasource_for_component(&self, component_id: &str) -> Option<&DataSource> {
        let ds_id = self.datacomponent_to_datasource.get(component_id)?;
        self.data_sources.get(ds_id)
    }

    pub fn get_components_for_datasource(&self, datasource_id: &str) -> Vec<&DataComponent> {
        self.datacomponent_to_datasource.iter()
            .filter(|(_, ds_id)| ds_id.as_str() == datasource_id)
            .filter_map(|(dc_id, _)| self.data_components.get(dc_id))
            .collect()
    }

    pub fn get_parent_technique(&self, subtechnique_id: &str) -> Option<&Technique> {
        let parent_id = self.subtechnique_to_technique.get(subtechnique_id)?;
        self.techniques.get(parent_id)
    }

    pub fn get_subtechniques(&self, technique_id: &str) -> Vec<&Technique> {
        self.subtechnique_to_technique.iter()
            .filter(|(_, parent_id)| parent_id.as_str() == technique_id)
            .filter_map(|(sub_id, _)| self.techniques.get(sub_id))
            .collect()
    }

    pub fn get_groups_for_campaign(&self, campaign_id: &str) -> Vec<&Group> {
        self.campaign_to_group.get(campaign_id)
            .map(|ids| ids.iter().filter_map(|id| self.get_group(id)).collect())
            .unwrap_or_default()
    }

    pub fn get_techniques_for_campaign(&self, campaign_id: &str) -> Vec<&Technique> {
        self.campaign_to_technique.get(campaign_id)
            .map(|ids| ids.iter().filter_map(|id| self.get_technique(id)).collect())
            .unwrap_or_default()
    }

    pub fn get_software_for_campaign(&self, campaign_id: &str) -> Vec<&Software> {
        self.campaign_to_software.get(campaign_id)
            .map(|ids| ids.iter().filter_map(|id| self.get_software(id)).collect())
            .unwrap_or_default()
    }

    pub fn find_technique_by_name(&self, name: &str) -> Option<&Technique> {
        let name_lower = name.to_lowercase();
        self.techniques.values()
            .find(|t| t.name.to_lowercase().contains(&name_lower))
    }

    pub fn tactics(&self) -> impl Iterator<Item = &Tactic> { self.tactics.values() }
    pub fn techniques(&self) -> impl Iterator<Item = &Technique> { self.techniques.values() }
    pub fn groups(&self) -> impl Iterator<Item = &Group> { self.groups.values() }
    pub fn software(&self) -> impl Iterator<Item = &Software> { self.software.values() }
    pub fn mitigations(&self) -> impl Iterator<Item = &Mitigation> { self.mitigations.values() }
    pub fn data_sources(&self) -> impl Iterator<Item = &DataSource> { self.data_sources.values() }
    pub fn data_components(&self) -> impl Iterator<Item = &DataComponent> { self.data_components.values() }
    pub fn campaigns(&self) -> impl Iterator<Item = &Campaign> { self.campaigns.values() }
    pub fn matrices(&self) -> impl Iterator<Item = &Matrix> { self.matrices.values() }
    pub fn analytics(&self) -> impl Iterator<Item = &Analytic> { self.analytics.values() }
    pub fn detection_strategies(&self) -> impl Iterator<Item = &DetectionStrategy> { self.detection_strategies.values() }
}
