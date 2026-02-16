use clap::{Parser, Subcommand};
use attack::{AttackStore, Validator, AttackObject, Technique};
use stix_rs::StixObject;
use std::io::Write;

#[derive(Parser)]
#[command(name = "attack")]
#[command(about = "MITRE ATT&CK CLI Tool", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Downloads enterprise-attack.json to local cache.
    Fetch {
        #[arg(default_value = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json")]
        url: String,
        #[arg(short, long, default_value = "enterprise-attack.json")]
        output: String,
    },
    /// Lookup a technique by T-Code (e.g., T1059) or Name.
    Lookup {
        query: String,
        #[arg(short, long, default_value = "enterprise-attack.json")]
        file: String,
    },
    /// Validate a list of IDs.
    Validate {
        ids: Vec<String>,
        #[arg(short, long, default_value = "enterprise-attack.json")]
        file: String,
    },
    /// Renders the hierarchy (Tactic -> Technique -> Sub-technique).
    Matrix {
        #[arg(short, long, default_value = "enterprise-attack.json")]
        file: String,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Fetch { url, output } => {
            println!("Fetching ATT&CK data from {}...", url);
            let resp = reqwest::blocking::get(url)?;
            let content = resp.bytes()?;
            let mut file = std::fs::File::create(&output)?;
            file.write_all(&content)?;
            println!("Saved to {}", output);
        }
        Commands::Lookup { query, file } => {
            let store = AttackStore::from_file(file)?;
            if let Some(tech) = store.get_technique_by_tcode(&query) {
                print_technique(&store, tech);
            } else if let Some(tech) = store.find_technique_by_name(&query) {
                print_technique(&store, tech);
            } else {
                println!("No technique found for '{}'", query);
            }
        }
        Commands::Validate { ids, file } => {
            let store = AttackStore::from_file(file)?;
            let validator = Validator::new(&store);
            for id in ids {
                let res = validator.validate_id(&id);
                println!("{}: {:?}", id, res);
            }
        }
        Commands::Matrix { file } => {
            let store = AttackStore::from_file(file)?;
            let mut tactic_to_techs: std::collections::HashMap<String, Vec<&Technique>> = std::collections::HashMap::new();
            
            for tech in store.techniques() {
                for tactic_shortname in tech.tactics() {
                    tactic_to_techs.entry(tactic_shortname.to_string()).or_default().push(tech);
                }
            }

            let mut tactics: Vec<_> = store.tactics().collect();
            tactics.sort_by_key(|t| &t.name);

            for tactic in tactics {
                println!("\n[ Tactic: {} ({}) ]", tactic.name, tactic.shortname);
                if let Some(techs) = tactic_to_techs.get(&tactic.shortname) {
                    let mut techs = techs.clone();
                    techs.sort_by_key(|t| t.tcode().unwrap_or(""));
                    for tech in techs {
                        let tcode = tech.tcode().unwrap_or("????");
                        if tech.is_subtechnique {
                            println!("  └── {}: {}", tcode, tech.name);
                        } else {
                            println!("  • {}: {}", tcode, tech.name);
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

fn print_technique(store: &AttackStore, tech: &Technique) {

    println!("\n=== Technique Details ===");
    println!("Name: {}", tech.name);
    println!("ID:   {}", tech.id());
    if let Some(tcode) = tech.tcode() {
        println!("T-Code: {}", tcode);
    }
    println!("Sub-technique: {}", tech.is_subtechnique);
    println!("Description: {}", tech.description.as_deref().unwrap_or("No description"));
    println!("Platforms:   {}", tech.platforms.join(", "));
    println!("Tactics:     {}", tech.tactics().join(", "));

    let groups = store.get_groups_using_technique(tech.id());
    if !groups.is_empty() {
        println!("\nUsed by Groups:");
        for group in groups {
            println!("  • {} ({})", group.name(), group.id());
        }
    }

    let mitigations = store.get_mitigations_for_technique(tech.id());
    if !mitigations.is_empty() {
        println!("\nMitigations:");
        for mitigation in mitigations {
            println!("  • {} ({})", mitigation.name(), mitigation.id());
        }
    }

    let datasources = store.get_datasources_for_technique(tech.id());
    if !datasources.is_empty() {
        println!("\nData Sources:");
        for ds in datasources {
            println!("  • {} ({})", ds.name(), ds.id());
        }
    }

    let datacomponents = store.get_datacomponents_for_technique(tech.id());
    if !datacomponents.is_empty() {
        println!("\nData Components:");
        for dc in datacomponents {
            println!("  • {} ({})", dc.name(), dc.id());
        }
    }

    if tech.is_subtechnique {
        if let Some(parent) = store.get_parent_technique(tech.id()) {
            println!("\nParent Technique: {} ({})", parent.name(), parent.tcode().unwrap_or(""));
        }
    } else {
        let subtechs = store.get_subtechniques(tech.id());
        if !subtechs.is_empty() {
            println!("\nSub-techniques:");
            for sub in subtechs {
                println!("  • {}: {}", sub.tcode().unwrap_or(""), sub.name());
            }
        }
    }
}
