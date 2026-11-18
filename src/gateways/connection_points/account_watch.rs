//! Checks that the mediator still holds each Connection Point's account.
//!
//! The mediator can lose accounts while the WebSocket stays open, for example
//! when its store is flushed or fails over. It recreates an account only when
//! that account sends, and refuses delivery to a missing one, so a Connection
//! Point that only receives would stay unreachable. Every active listener's
//! own account is therefore probed on an interval and repaired, a few listeners
//! at a time.

use std::sync::{Arc, Weak};
use std::time::Duration;

use affinidi_messaging_sdk::errors::ATMError;
use affinidi_messaging_sdk::tasks::messaging::account::get::v0_2::Account;
use futures::StreamExt;
use tracing::{debug, warn};

use super::ws_listener::{ConnectionPointListenerManager, ConnectionStatus, ListenerInfo};
use crate::comm::didcomm::client::DIDCommClient;
use crate::mediators::utils::{InboundAcl, apply_inbound_acl};

const ACCOUNT_CHECK_INTERVAL: Duration = Duration::from_secs(30);

/// How long the mediator may take to return the Connection Point's account.
const ACCOUNT_PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// How long a restarted listener may take to re-authenticate and re-register.
const LISTENER_RESTART_TIMEOUT: Duration = Duration::from_secs(20);

/// How long the mediator may take to re-open a closed receive list.
const RECEIVE_LIST_REOPEN_TIMEOUT: Duration = Duration::from_secs(10);

/// How many listeners are checked at once.
const CONCURRENT_ACCOUNT_CHECKS: usize = 4;

/// How soon an account whose probe timed out is probed again, instead of
/// waiting a whole [`ACCOUNT_CHECK_INTERVAL`]. Only the listeners that timed
/// out are re-probed on that pass, so a mediator that cannot answer for one
/// Connection Point does not pull every other one into a faster cadence.
const UNANSWERED_RECHECK_INTERVAL: Duration = Duration::from_secs(5);

/// How many probes in a row may go unanswered before the listener is restarted
/// anyway. A mediator that has lost the account cannot deliver its own answer
/// to it either, so the probe times out instead of being refused; waiting for a
/// refusal that cannot arrive would leave the Connection Point unreachable.
/// Only a timeout counts: a probe the mediator did answer, even with a refusal
/// or an error, says the socket still carries traffic.
const UNANSWERED_RESTART_LIMIT: u32 = 2;

/// What [`ATMError::mediator_code`] reads out of the problem report a mediator
/// before v0.52 answers with when it no longer has the requesting account
/// (`e.p.account.not_found`): its descriptor, without the `e.p.` prefix.
const ACCOUNT_NOT_FOUND_DESCRIPTOR: &str = "account.not_found";

/// The Trust Task code a mediator from v0.52 refuses `messaging/account/get`
/// with when it no longer has the account. It arrives in a `trust-task-error`
/// document, not a problem report.
const UNKNOWN_ACCOUNT_CODE: &str =
    affinidi_messaging_sdk::tasks::messaging::account::get::v0_2::error_codes::UNKNOWN_ACCOUNT.code;

pub(crate) type AccountProbe = Result<Result<Account, ATMError>, tokio::time::error::Elapsed>;

/// What a probe of the Connection Point's own mediator account calls for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AccountRepair {
    /// The account accepts messages, or it could not be read.
    Nothing,
    /// The mediator no longer has the account: restart the listener so it
    /// re-authenticates and re-registers.
    RestartListener,
    /// The account exists but its access-list mode is not the one the
    /// connection point should have: re-apply its inbound ACL.
    ReopenReceiveList,
}

/// What [`check_listener`] did with one listener.
#[derive(Debug, Clone, PartialEq, Eq)]
enum AccountCheck {
    /// The listener is not connected, so its mediator session is not probed.
    Skipped,
    /// The mediator answered, but not with the account, so nothing was changed.
    Unreadable,
    /// The mediator did not answer the probe at all.
    Unanswered,
    /// The account accepts messages.
    Healthy,
    /// The account needed `repair`, with the repair's outcome.
    Repaired(AccountRepair, Result<(), String>),
}

/// The mediator calls a check makes for one listener.
#[async_trait::async_trait]
trait MediatorAccount: Sync {
    async fn probe(
        &self,
        listener: &ListenerInfo,
    ) -> AccountProbe;

    async fn reopen_receive_list(
        &self,
        listener: &ListenerInfo,
    ) -> Result<(), String>;
}

/// The listener's own mediator session.
struct ListenerSession;

#[async_trait::async_trait]
impl MediatorAccount for ListenerSession {
    async fn probe(
        &self,
        listener: &ListenerInfo,
    ) -> AccountProbe {
        probe_own_account(&listener.client).await
    }

    async fn reopen_receive_list(
        &self,
        listener: &ListenerInfo,
    ) -> Result<(), String> {
        apply_inbound_acl(listener.client.atm(), Arc::clone(listener.client.profile()), &listener.inbound_acl).await
    }
}

pub(crate) async fn probe_own_account(client: &DIDCommClient) -> AccountProbe {
    tokio::time::timeout(
        ACCOUNT_PROBE_TIMEOUT,
        client
            .atm()
            .trust_tasks()
            .account_get(client.profile(), None),
    )
    .await
}

/// What `probe` of a connection point whose account should carry `intended`
/// calls for.
pub(crate) fn account_repair(
    probe: &AccountProbe,
    intended: &InboundAcl,
) -> AccountRepair {
    match probe {
        Ok(Ok(account)) => {
            let as_intended = account
                .acl
                .access_list_mode
                .as_ref()
                .is_some_and(|mode| mode.to_string() == intended.access_list_mode());
            if as_intended {
                AccountRepair::Nothing
            } else {
                AccountRepair::ReopenReceiveList
            }
        }
        Ok(Err(error)) if is_account_not_found(error) => AccountRepair::RestartListener,
        Ok(Err(_)) | Err(_) => AccountRepair::Nothing,
    }
}

/// Whether the mediator refused the probe because it no longer holds the
/// account, in either form it answers with: the problem report of a mediator
/// before v0.52, or the `trust-task-error` document every later one sends.
fn is_account_not_found(error: &ATMError) -> bool {
    error
        .mediator_code()
        .is_some_and(says_the_account_is_gone)
}

/// Whether `code` is a mediator saying it no longer holds *our* account: the
/// descriptor of the problem report a mediator before v0.52 answers with, or
/// the code `messaging/account/get` declares for it. Any other task's
/// `unknownAccount` may be about a peer's account, not ours.
pub(crate) fn says_the_account_is_gone(code: &str) -> bool {
    code == ACCOUNT_NOT_FOUND_DESCRIPTOR || code == UNKNOWN_ACCOUNT_CODE
}

/// How often each listener's probe has gone unanswered in a row, and which of
/// them the next pass should visit.
#[derive(Debug, Default)]
struct UnansweredProbes {
    consecutive: std::collections::HashMap<String, u32>,
}

impl UnansweredProbes {
    /// Whether another unanswered probe of `connection_point_id` restarts its
    /// listener: on the second unanswered probe in a row, and then at doubling
    /// counts, so a mediator that stays silent is retried ever more slowly
    /// instead of on every pass.
    fn restart_due(
        &self,
        connection_point_id: &str,
    ) -> bool {
        let consecutive = self
            .consecutive
            .get(connection_point_id)
            .copied()
            .unwrap_or(0)
            .saturating_add(1);
        consecutive >= UNANSWERED_RESTART_LIMIT && consecutive.is_power_of_two()
    }

    /// Records one pass: how long to wait before the next one, and which
    /// listeners it should visit — only those whose probe went unanswered, so
    /// a mediator silent for one Connection Point does not pull every other
    /// one into the faster cadence. An empty set means every listener.
    fn record(
        &mut self,
        pass: &[(String, AccountCheck)],
    ) -> (Duration, std::collections::HashSet<String>) {
        let seen: std::collections::HashSet<&str> = pass
            .iter()
            .map(|(connection_point_id, _)| connection_point_id.as_str())
            .collect();
        self.consecutive
            .retain(|connection_point_id, _| seen.contains(connection_point_id.as_str()));

        let mut unanswered = std::collections::HashSet::new();
        for (connection_point_id, check) in pass {
            let consecutive = self
                .consecutive
                .entry(connection_point_id.clone())
                .or_insert(0);
            if matches!(check, AccountCheck::Unanswered) {
                *consecutive = consecutive.saturating_add(1);
                unanswered.insert(connection_point_id.clone());
            } else {
                // Any answer, including a refusal and a restart that followed
                // the silence, starts the count again.
                *consecutive = 0;
            }
        }

        let delay = if unanswered.is_empty() {
            ACCOUNT_CHECK_INTERVAL
        } else {
            UNANSWERED_RECHECK_INTERVAL
        };
        (delay, unanswered)
    }
}

/// Probes every active listener's account on an interval until the manager
/// is dropped.
pub(crate) fn spawn(manager: Weak<ConnectionPointListenerManager>) {
    crate::observability::spawn_traced_task("connection_points.account_watch", async move {
        let mut unanswered = UnansweredProbes::default();
        let mut delay = ACCOUNT_CHECK_INTERVAL;
        let mut focus: std::collections::HashSet<String> = std::collections::HashSet::new();
        loop {
            tokio::time::sleep(delay).await;
            let Some(manager) = manager.upgrade() else {
                break;
            };
            let listeners: Vec<ListenerInfo> = manager
                .get_active_listeners()
                .await
                .into_iter()
                .filter(|listener| focus.is_empty() || focus.contains(&listener.connection_point_id))
                .collect();
            let pass = futures::stream::iter(listeners)
                .map(|listener| {
                    let manager = &manager;
                    let restart_due = unanswered.restart_due(&listener.connection_point_id);
                    async move {
                        let check = check_listener(manager, &listener, &ListenerSession, restart_due).await;
                        (listener.connection_point_id, check)
                    }
                })
                .buffer_unordered(CONCURRENT_ACCOUNT_CHECKS)
                .collect::<Vec<_>>()
                .await;
            (delay, focus) = unanswered.record(&pass);
        }
    });
}

/// Probes one listener's account and performs the repair it calls for.
/// `restart_due` says this listener's probe has gone unanswered often enough
/// that another silent probe restarts it; the restart runs here, inside the
/// caller's bounded concurrency, rather than serially after the pass.
async fn check_listener(
    manager: &ConnectionPointListenerManager,
    listener: &ListenerInfo,
    mediator: &impl MediatorAccount,
    restart_due: bool,
) -> AccountCheck {
    let connected = matches!(
        listener
            .metrics
            .read()
            .await
            .status,
        ConnectionStatus::Connected
    );
    if !connected {
        return AccountCheck::Skipped;
    }

    let probe = mediator.probe(listener).await;
    let unanswered = probe.is_err();
    let repair = match account_repair(&probe, &listener.inbound_acl) {
        // The mediator never answered, and it has not answered the probes
        // before this one either: restart rather than wait for a refusal that
        // a lost account cannot receive.
        AccountRepair::Nothing if unanswered && restart_due => AccountRepair::RestartListener,
        repair => repair,
    };
    let repaired = match repair {
        AccountRepair::Nothing if unanswered => {
            debug!(connection_point = %listener.name, "The mediator did not answer the account probe; leaving the listener as it is");
            return AccountCheck::Unanswered;
        }
        AccountRepair::Nothing if !matches!(probe, Ok(Ok(_))) => {
            debug!(connection_point = %listener.name, "Could not read the mediator account; leaving the listener as it is");
            return AccountCheck::Unreadable;
        }
        AccountRepair::Nothing => return AccountCheck::Healthy,
        AccountRepair::RestartListener => {
            if unanswered {
                warn!(
                    connection_point = %listener.name,
                    "The mediator has not answered this Connection Point's account probe; restarting it to re-authenticate and re-register"
                );
            } else {
                warn!(
                    connection_point = %listener.name,
                    "The mediator no longer has this Connection Point's account; restarting it to re-authenticate and re-register"
                );
            }
            manager
                .restart_listener_if_current(
                    &listener.connection_point_id,
                    &listener.instance_id,
                    LISTENER_RESTART_TIMEOUT,
                )
                .await
                .map(|_| ())
        }
        AccountRepair::ReopenReceiveList => {
            warn!(
                connection_point = %listener.name,
                "The mediator account's receive list is closed; re-opening it"
            );
            tokio::time::timeout(RECEIVE_LIST_REOPEN_TIMEOUT, mediator.reopen_receive_list(listener))
                .await
                .unwrap_or_else(|_| Err(format!("timed out after {RECEIVE_LIST_REOPEN_TIMEOUT:?}")))
        }
    };
    if let Err(error) = &repaired {
        warn!(connection_point = %listener.name, ?repair, "Repairing the mediator account failed: {error}");
    }
    AccountCheck::Repaired(repair, repaired)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probed_account(access_list_mode: &str) -> AccountProbe {
        Ok(Ok(serde_json::from_value(serde_json::json!({
            "did": "did:example:connection-point",
            "accountType": "standard",
            "acl": { "accessListMode": access_list_mode }
        }))
        .unwrap()))
    }

    fn probe_error(error: ATMError) -> AccountProbe {
        Ok(Err(error))
    }

    /// A mediator from v0.52 refuses with a `trust-task-error` document
    /// instead of a problem report, under the Trust Task code.
    fn refusal(code: &str) -> ATMError {
        let document = serde_json::json!({
            "id": "urn:uuid:1",
            "type": "https://trusttasks.org/spec/trust-task-error/0.6",
            "threadId": "urn:uuid:2",
            "payload": {
                "code": code,
                "message": "account not found",
                "retryable": false,
            },
        });
        ATMError::TrustTaskError(Box::new(
            affinidi_messaging_sdk::errors::TrustTaskRefusal::from_document(&document).expect("a trust-task-error"),
        ))
    }

    #[test]
    fn account_not_found_is_recognised_only_from_its_problem_report() {
        let missing = ATMError::ProblemReport("e.p.account.not_found".into(), "gone".into(), "false".into());
        assert!(is_account_not_found(&missing));

        let other_report = ATMError::ProblemReport("e.p.access_list.denied".into(), "denied".into(), "false".into());
        assert!(!is_account_not_found(&other_report));

        let transport = ATMError::TransportError("account.not_found".into());
        assert!(!is_account_not_found(&transport));

        let near_miss = ATMError::ProblemReport("e.p.account.not_found_else".into(), "other".into(), "false".into());
        assert!(!is_account_not_found(&near_miss));
    }

    #[test]
    fn account_not_found_is_recognised_from_a_trust_task_refusal() {
        assert!(is_account_not_found(&refusal(UNKNOWN_ACCOUNT_CODE)));
        assert!(!is_account_not_found(&refusal("messaging/account/get:notAuthorised")));
    }

    #[tokio::test]
    async fn a_trust_task_refusal_restarts_the_listener() {
        assert_eq!(
            account_repair(&probe_error(refusal(UNKNOWN_ACCOUNT_CODE)), &InboundAcl::Open),
            AccountRepair::RestartListener
        );
        assert_eq!(
            account_repair(&probe_error(refusal("messaging/account/get:notAuthorised")), &InboundAcl::Open),
            AccountRepair::Nothing
        );
    }

    #[tokio::test]
    async fn only_a_missing_account_restarts_the_listener() {
        let missing =
            probe_error(ATMError::ProblemReport("e.p.account.not_found".into(), "gone".into(), "false".into()));
        assert_eq!(account_repair(&missing, &InboundAcl::Open), AccountRepair::RestartListener);

        let other_report =
            probe_error(ATMError::ProblemReport("e.p.access_list.denied".into(), "denied".into(), "false".into()));
        assert_eq!(account_repair(&other_report, &InboundAcl::Open), AccountRepair::Nothing);

        let near_miss =
            probe_error(ATMError::ProblemReport("e.p.account.not_found_else".into(), "other".into(), "false".into()));
        assert_eq!(account_repair(&near_miss, &InboundAcl::Open), AccountRepair::Nothing);

        let transport = probe_error(ATMError::TransportError("connection reset".into()));
        assert_eq!(account_repair(&transport, &InboundAcl::Open), AccountRepair::Nothing);

        let probe_timed_out: AccountProbe = Err(tokio::time::timeout(Duration::ZERO, std::future::pending::<()>())
            .await
            .unwrap_err());
        assert_eq!(account_repair(&probe_timed_out, &InboundAcl::Open), AccountRepair::Nothing);
    }

    #[test]
    fn only_a_closed_receive_list_is_reopened_on_an_open_connection_point() {
        assert_eq!(account_repair(&probed_account("explicitDeny"), &InboundAcl::Open), AccountRepair::Nothing);
        assert_eq!(
            account_repair(&probed_account("explicitAllow"), &InboundAcl::Open),
            AccountRepair::ReopenReceiveList
        );
    }

    #[test]
    fn a_paired_connection_point_keeps_its_peer_only_list_and_regains_it_when_opened() {
        let peer_only = InboundAcl::Peers(vec!["did:example:peer".into()]);
        assert_eq!(account_repair(&probed_account("explicitAllow"), &peer_only), AccountRepair::Nothing);
        assert_eq!(
            account_repair(&probed_account("explicitDeny"), &peer_only),
            AccountRepair::ReopenReceiveList,
            "an account opened to everyone is narrowed back to its peer"
        );
    }

    /// A mediator that answers every probe with `probe`, and counts the
    /// receive-list re-openings, each taking `reopen_delay`.
    struct StubMediator {
        probe: fn() -> AccountProbe,
        /// A mediator that never answers the probe, as one that has lost the
        /// account cannot: it has nowhere to deliver its own answer.
        silent: bool,
        reopen_delay: Duration,
        reopened: std::sync::atomic::AtomicUsize,
    }

    impl StubMediator {
        fn answering(probe: fn() -> AccountProbe) -> Self {
            Self {
                probe,
                silent: false,
                reopen_delay: Duration::ZERO,
                reopened: Default::default(),
            }
        }

        fn silent() -> Self {
            Self {
                silent: true,
                ..Self::answering(|| probed_account("explicitDeny"))
            }
        }

        fn reopened(&self) -> usize {
            self.reopened
                .load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl MediatorAccount for StubMediator {
        async fn probe(
            &self,
            _: &ListenerInfo,
        ) -> AccountProbe {
            if self.silent {
                return Err(tokio::time::timeout(Duration::ZERO, std::future::pending::<()>())
                    .await
                    .unwrap_err());
            }
            (self.probe)()
        }

        async fn reopen_receive_list(
            &self,
            _: &ListenerInfo,
        ) -> Result<(), String> {
            self.reopened
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            tokio::time::sleep(self.reopen_delay).await;
            Ok(())
        }
    }

    fn missing_account() -> AccountProbe {
        probe_error(ATMError::ProblemReport("e.p.account.not_found".into(), "gone".into(), "false".into()))
    }

    /// A manager running one connected listener, `instance_id`.
    async fn connected_listener(
        root: &std::path::Path,
        instance_id: &str,
    ) -> (ConnectionPointListenerManager, ListenerInfo, tempfile::TempDir) {
        let (manager, issuer_dir) = crate::gateways::test_helpers::test_listener_manager(root).await;
        let listener = crate::gateways::test_helpers::test_listener(instance_id).await;
        listener
            .metrics
            .write()
            .await
            .status = ConnectionStatus::Connected;
        manager
            .register_test_listener(listener.clone())
            .await;
        (manager, listener, issuer_dir)
    }

    #[tokio::test]
    async fn a_listener_that_is_not_connected_is_not_probed() {
        let root = tempfile::TempDir::new().unwrap();
        let (manager, listener, _issuer_dir) = connected_listener(root.path(), "reconnecting").await;
        let mediator = StubMediator::answering(missing_account);

        for status in [ConnectionStatus::Reconnecting, ConnectionStatus::Failed] {
            listener
                .metrics
                .write()
                .await
                .status = status;
            assert_eq!(check_listener(&manager, &listener, &mediator, false).await, AccountCheck::Skipped);
        }
    }

    #[tokio::test]
    async fn an_open_account_is_left_alone_and_an_unreadable_one_is_reported() {
        let root = tempfile::TempDir::new().unwrap();
        let (manager, listener, _issuer_dir) = connected_listener(root.path(), "probed").await;

        let open = StubMediator::answering(|| probed_account("explicitDeny"));
        assert_eq!(check_listener(&manager, &listener, &open, false).await, AccountCheck::Healthy);
        assert_eq!(open.reopened(), 0);

        let unreachable = StubMediator::answering(|| probe_error(ATMError::TransportError("connection reset".into())));
        assert_eq!(check_listener(&manager, &listener, &unreachable, false).await, AccountCheck::Unreadable);
        assert_eq!(unreachable.reopened(), 0);
        assert!(
            manager
                .get_listener("cp-1")
                .await
                .is_some_and(|current| current.instance_id == "probed"),
            "the listener keeps running"
        );
    }

    #[tokio::test]
    async fn a_closed_receive_list_is_reopened_within_its_timeout() {
        let root = tempfile::TempDir::new().unwrap();
        let (manager, listener, _issuer_dir) = connected_listener(root.path(), "probed").await;

        let closed = StubMediator::answering(|| probed_account("explicitAllow"));
        assert_eq!(
            check_listener(&manager, &listener, &closed, false).await,
            AccountCheck::Repaired(AccountRepair::ReopenReceiveList, Ok(()))
        );
        assert_eq!(closed.reopened(), 1);

        tokio::time::pause();
        let hanging = StubMediator {
            reopen_delay: RECEIVE_LIST_REOPEN_TIMEOUT * 2,
            ..StubMediator::answering(|| probed_account("explicitAllow"))
        };
        assert_eq!(
            check_listener(&manager, &listener, &hanging, false).await,
            AccountCheck::Repaired(
                AccountRepair::ReopenReceiveList,
                Err(format!("timed out after {RECEIVE_LIST_REOPEN_TIMEOUT:?}"))
            )
        );
    }

    #[tokio::test]
    async fn a_missing_account_restarts_only_the_listener_that_was_probed() {
        let root = tempfile::TempDir::new().unwrap();
        let (manager, listener, _issuer_dir) = connected_listener(root.path(), "probed").await;
        let mediator = StubMediator::answering(missing_account);

        assert_eq!(
            check_listener(&manager, &listener, &mediator, false).await,
            AccountCheck::Repaired(AccountRepair::RestartListener, Err("Connection point 'cp-1' not found".into())),
            "the restart reads the Connection Point to start it again"
        );

        let replacement = crate::gateways::test_helpers::test_listener("replacement").await;
        manager
            .register_test_listener(replacement)
            .await;
        assert_eq!(
            check_listener(&manager, &listener, &mediator, false).await,
            AccountCheck::Repaired(AccountRepair::RestartListener, Ok(())),
            "a listener another caller replaced is kept"
        );
        assert_eq!(mediator.reopened(), 0);
    }

    #[tokio::test]
    async fn an_unanswered_probe_restarts_the_listener_only_when_one_is_due() {
        let root = tempfile::TempDir::new().unwrap();
        let (manager, listener, _issuer_dir) = connected_listener(root.path(), "probed").await;
        let silent = StubMediator::silent();

        assert_eq!(
            check_listener(&manager, &listener, &silent, false).await,
            AccountCheck::Unanswered,
            "a first silent probe is tolerated"
        );
        assert_eq!(
            check_listener(&manager, &listener, &silent, true).await,
            AccountCheck::Repaired(AccountRepair::RestartListener, Err("Connection point 'cp-1' not found".into())),
            "a silent probe restarts the listener once one is due"
        );
    }

    fn pass(outcomes: &[(&str, AccountCheck)]) -> Vec<(String, AccountCheck)> {
        outcomes
            .iter()
            .map(|(connection_point_id, check)| ((*connection_point_id).to_string(), check.clone()))
            .collect()
    }

    #[test]
    fn only_consecutive_silence_makes_a_restart_due() {
        let mut probes = UnansweredProbes::default();

        assert!(!probes.restart_due("cp-1"), "the first unanswered probe is tolerated");
        probes.record(&pass(&[("cp-1", AccountCheck::Unanswered)]));
        assert!(probes.restart_due("cp-1"), "the second in a row is not");

        probes.record(&pass(&[("cp-1", AccountCheck::Healthy)]));
        assert!(!probes.restart_due("cp-1"), "an answered probe starts the count again");

        probes.record(&pass(&[("cp-1", AccountCheck::Unanswered)]));
        assert!(probes.restart_due("cp-1"));
        probes.record(&pass(&[("cp-1", AccountCheck::Repaired(AccountRepair::RestartListener, Ok(())))]));
        assert!(!probes.restart_due("cp-1"), "a restart answers the silence");
    }

    #[test]
    fn a_mediator_that_stays_silent_is_restarted_ever_more_slowly() {
        let mut probes = UnansweredProbes::default();
        let due = (0..16)
            .map(|_| {
                let due = probes.restart_due("cp-1");
                probes.record(&pass(&[("cp-1", AccountCheck::Unanswered)]));
                due
            })
            .enumerate()
            .filter_map(|(probe, due)| due.then_some(probe + 1))
            .collect::<Vec<_>>();

        assert_eq!(due, [2, 4, 8, 16], "restarts back off instead of repeating every pass");
    }

    #[test]
    fn only_the_listeners_that_went_unanswered_are_probed_again_sooner() {
        let mut probes = UnansweredProbes::default();

        let (delay, focus) =
            probes.record(&pass(&[("cp-1", AccountCheck::Healthy), ("cp-2", AccountCheck::Unreadable)]));
        assert_eq!(delay, ACCOUNT_CHECK_INTERVAL, "an answered refusal keeps the usual cadence");
        assert!(focus.is_empty(), "every listener is probed on the next pass");

        let (delay, focus) =
            probes.record(&pass(&[("cp-1", AccountCheck::Healthy), ("cp-2", AccountCheck::Unanswered)]));
        assert_eq!(delay, UNANSWERED_RECHECK_INTERVAL);
        assert_eq!(focus, std::collections::HashSet::from(["cp-2".to_string()]), "only the silent one");
        assert!(UNANSWERED_RECHECK_INTERVAL < ACCOUNT_CHECK_INTERVAL);
    }

    #[test]
    fn a_listener_that_is_gone_is_forgotten() {
        let mut probes = UnansweredProbes::default();
        probes.record(&pass(&[("cp-1", AccountCheck::Unanswered)]));
        assert!(probes.restart_due("cp-1"));

        probes.record(&pass(&[("cp-2", AccountCheck::Healthy)]));
        assert!(!probes.restart_due("cp-1"), "a listener no longer checked keeps no count");
    }
}
