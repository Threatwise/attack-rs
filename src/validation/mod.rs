use crate::store::AttackStore;
use crate::domain::AttackObject;

#[derive(Debug, PartialEq, Eq)]
pub enum ValidationResult {
    Valid,
    Deprecated { replaced_by: Option<String> },
    Revoked { replaced_by: Option<String> },
    Unknown,
}

pub struct Validator<'a> {
    store: &'a AttackStore,
}

impl<'a> Validator<'a> {
    pub fn new(store: &'a AttackStore) -> Self {
        Self { store }
    }

    pub fn validate_id(&self, id: &str) -> ValidationResult {
        if let Some(obj) = self.get_any_object(id) {
            if obj.revoked() {
                ValidationResult::Revoked { replaced_by: self.get_replacement(id) }
            } else if obj.deprecated() {
                ValidationResult::Deprecated { replaced_by: self.get_replacement(id) }
            } else {
                ValidationResult::Valid
            }
        } else {
            ValidationResult::Unknown
        }
    }

    fn get_any_object(&self, id: &str) -> Option<&dyn AttackObject> {
        if let Some(o) = self.store.get_tactic(id) { return Some(o); }
        if let Some(o) = self.store.get_technique(id) { return Some(o); }
        if let Some(o) = self.store.get_group(id) { return Some(o); }
        if let Some(o) = self.store.get_software(id) { return Some(o); }
        if let Some(o) = self.store.get_mitigation(id) { return Some(o); }
        if let Some(o) = self.store.get_data_source(id) { return Some(o); }
        if let Some(o) = self.store.get_data_component(id) { return Some(o); }
        if let Some(o) = self.store.get_campaign(id) { return Some(o); }
        if let Some(o) = self.store.get_matrix(id) { return Some(o); }
        if let Some(o) = self.store.get_analytic(id) { return Some(o); }
        if let Some(o) = self.store.get_detection_strategy(id) { return Some(o); }
        None
    }

    fn get_replacement(&self, id: &str) -> Option<String> {
        self.store.get_replacement(id).map(|s| s.to_string())
    }
}
