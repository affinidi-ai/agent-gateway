#[path = "bdd_support/mod.rs"]
mod bdd_support;
#[path = "g2g_bdd/harness/mod.rs"]
mod harness;
#[path = "g2g_bdd/steps/mod.rs"]
mod steps;
#[path = "g2g_bdd/world.rs"]
mod world;

use bdd_support::mediator::{MediatorEnvCheck, ScenarioDockerMediator, configured_parallelism};
use bdd_support::tags::{include_known_bugs_from_env, should_run_for_tags};
use cucumber::World;

use world::G2gWorld;

#[tokio::main]
async fn main() {
    let parallelism = match configured_parallelism() {
        Ok(parallelism) => parallelism,
        Err(message) => {
            eprintln!("{message}");
            std::process::exit(2);
        }
    };

    match ScenarioDockerMediator::validate_env(parallelism) {
        Ok(MediatorEnvCheck::Run) => {}
        Ok(MediatorEnvCheck::Skip(message)) => {
            eprintln!("{message}");
            return;
        }
        Err(message) => {
            eprintln!("{message}");
            std::process::exit(2);
        }
    }

    let include_known_bugs = include_known_bugs_from_env();
    let feature_path = std::env::var("BDD_FEATURE_PATH").unwrap_or_else(|_| "tests/features/g2g".to_string());

    eprintln!("Running g2g_bdd with scenario parallelism: {parallelism}");
    if feature_path != "tests/features/g2g" {
        eprintln!("Feature path: {feature_path}");
    }

    G2gWorld::cucumber()
        .max_concurrent_scenarios(Some(parallelism))
        .filter_run_and_exit(feature_path, move |feature, rule, scenario| {
            should_run_for_tags(
                feature
                    .tags
                    .iter()
                    .chain(
                        rule.iter()
                            .flat_map(|rule| rule.tags.iter()),
                    )
                    .chain(scenario.tags.iter()),
                include_known_bugs,
                false,
            )
        })
        .await;
}
