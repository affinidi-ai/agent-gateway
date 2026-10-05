#[path = "bdd_support/mod.rs"]
mod bdd_support;
#[path = "surface_bdd/steps/mod.rs"]
mod steps;
#[path = "surface_bdd/world.rs"]
mod world;

use bdd_support::tags::{include_known_bugs_from_env, should_run_for_tags};
use cucumber::World;
use world::SurfaceWorld;

const DEFAULT_MAX_CONCURRENT_SCENARIOS: usize = 4;

fn configured_parallelism(is_debug: bool) -> usize {
    if is_debug {
        return 1;
    }

    if let Ok(value) = std::env::var("BDD_MAX_CONCURRENT_SCENARIOS") {
        let value = value.trim();
        return value
            .parse::<usize>()
            .ok()
            .filter(|n| *n > 0)
            .unwrap_or_else(|| panic!("BDD_MAX_CONCURRENT_SCENARIOS must be a positive integer, got {value:?}"));
    }

    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(DEFAULT_MAX_CONCURRENT_SCENARIOS)
        .min(DEFAULT_MAX_CONCURRENT_SCENARIOS)
}

#[tokio::main]
async fn main() {
    let is_debug = std::env::var("DEBUG")
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false);
    let bdd_temp_dir_root = std::env::var("BDD_TEMP_DIR_ROOT").unwrap_or_else(|_| "Not set".to_string());
    let bdd_temp_dir_prefix = std::env::var("BDD_TEMP_DIR_PREFIX").unwrap_or_else(|_| "Not set".to_string());
    let parallelism = configured_parallelism(is_debug);
    let feature_path = std::env::var("BDD_FEATURE_PATH").unwrap_or_else(|_| "tests/features/surface".to_string());

    let include_known_bugs = include_known_bugs_from_env();

    if is_debug {
        eprintln!("Running with parallelism: {parallelism}");
        eprintln!("Including known bugs: {include_known_bugs}");
        eprintln!("Feature path: {feature_path}");
        eprintln!("BDD temp dir root: {bdd_temp_dir_root}");
        eprintln!("BDD temp dir prefix: {bdd_temp_dir_prefix}");
    }

    SurfaceWorld::cucumber()
        .max_concurrent_scenarios(Some(parallelism))
        .filter_run_and_exit(&feature_path, move |feature, rule, scenario| {
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
                is_debug,
            )
        })
        .await;
}
