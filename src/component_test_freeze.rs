const NEW_TESTS_GO_ELSEWHERE: &str = "src/component_tests is frozen: put new tests outside it, a Gherkin scenario under tests/features or a unit test beside the code (see docs/development/TESTING.md)";

const WHEN_A_PIN_MAY_RISE: &str = "raise a pin in FROZEN_FILES in src/component_tests/mod.rs only with a reason stated in the pull request; the usual one is matching main's count after a FROZEN_FILES merge conflict or when main itself fails this guard (a file main added gets an entry with main's count)";

pub(crate) fn refusal(
    label: &str,
    offenders: &[impl std::fmt::Debug],
) -> String {
    format!("{NEW_TESTS_GO_ELSEWHERE}; {label}: {offenders:?}; {WHEN_A_PIN_MAY_RISE}")
}

#[cfg(test)]
mod tests {
    use super::refusal;

    #[test]
    fn a_refusal_sends_new_tests_outside_the_folder() {
        let message = refusal("new files", &["new_flow_e2e.rs"]);

        assert!(message.contains("put new tests outside it"), "{message}");
        assert!(message.contains("docs/development/TESTING.md"), "{message}");
        assert!(!message.contains("if a rebase brought this in"), "{message}");
    }

    #[test]
    fn a_refusal_allows_a_raise_only_with_a_stated_reason() {
        let message = refusal("grown files", &["a2a_flow_e2e.rs has 52 tests, pinned at 51"]);

        assert!(message.contains("only with a reason stated in the pull request"), "{message}");
        assert!(
            message.contains("after a FROZEN_FILES merge conflict or when main itself fails this guard"),
            "{message}"
        );
        assert!(!message.contains("set its entry"), "{message}");
    }

    #[test]
    fn a_refusal_names_the_offenders_under_its_label() {
        let message = refusal("grown files", &["a2a_flow_e2e.rs has 52 tests, pinned at 51"]);

        assert!(message.contains("grown files: [\"a2a_flow_e2e.rs has 52 tests, pinned at 51\"]"), "{message}");
        assert!(!message.contains("new files"), "{message}");
    }
}
