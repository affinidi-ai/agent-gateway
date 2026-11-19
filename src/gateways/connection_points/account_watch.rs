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
    /// The mediator did not answer, and the listener was restarted for it,
    /// with the restart's outcome. Counted as silence, not as an answer: a
    /// mediator that keeps saying nothing must be restarted ever more slowly,
    /// which only works while the count survives the restart.
    UnansweredAndRestarted(Result<(), String>),
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

/// Which listeners a pass visits.
#[derive(Debug, PartialEq, Eq)]
enum PassScope {
    /// Every active listener, which also restarts the full-pass interval.
    Every,
    /// Only the listeners whose probe went unanswered, re-probed sooner.
    Only(std::collections::HashSet<String>),
}

/// Which listeners the next pass visits: only the silent ones while they are
/// being re-probed, and every listener once [`ACCOUNT_CHECK_INTERVAL`] has
/// passed since the last complete pass. Without that deadline a mediator that
/// never answers for one Connection Point would keep every other one from
/// being checked at all.
fn next_scope(
    focus: &std::collections::HashSet<String>,
    since_full_pass: Duration,
) -> PassScope {
    if focus.is_empty() || since_full_pass >= ACCOUNT_CHECK_INTERVAL {
        PassScope::Every
    } else {
        PassScope::Only(focus.clone())
    }
}

/// How long to wait before the next pass: what the pass itself calls for, but
/// never past the deadline for the next full one. Without the cap a pass that
/// ends with nothing silent — a listener skipped while it re-authenticates,
/// say — would start a fresh interval of its own, and the full sweep would
/// drift later than [`ACCOUNT_CHECK_INTERVAL`] after the last one.
fn next_delay(
    after_pass: Duration,
    since_full_pass: Duration,
) -> Duration {
    after_pass.min(ACCOUNT_CHECK_INTERVAL.saturating_sub(since_full_pass))
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
    /// instead of on every pass. A restart does not clear the count — only an
    /// answer does — so the gaps keep widening while the silence lasts.
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
        full: bool,
    ) -> (Duration, std::collections::HashSet<String>) {
        // Only a pass that visited every listener can say which ones are gone;
        // a pass narrowed to the silent ones leaves the rest untouched.
        if full {
            let seen: std::collections::HashSet<&str> = pass
                .iter()
                .map(|(connection_point_id, _)| connection_point_id.as_str())
                .collect();
            self.consecutive
                .retain(|connection_point_id, _| seen.contains(connection_point_id.as_str()));
        }

        let mut unanswered = std::collections::HashSet::new();
        for (connection_point_id, check) in pass {
            let consecutive = self
                .consecutive
                .entry(connection_point_id.clone())
                .or_insert(0);
            match check {
                AccountCheck::Unanswered | AccountCheck::UnansweredAndRestarted(_) => {
                    *consecutive = consecutive.saturating_add(1);
                    unanswered.insert(connection_point_id.clone());
                }
                // A listener that is not connected was not asked anything, so
                // it says nothing either way: its count stands. Resetting it
                // here would undo the backoff, since a listener restarted for
                // silence is often still re-authenticating at the next probe.
                AccountCheck::Skipped => {}
                // Any answer starts the count again, including a refusal: the
                // mediator is talking to this socket.
                _ => *consecutive = 0,
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
        let mut last_full_pass = tokio::time::Instant::now();
        loop {
            tokio::time::sleep(delay).await;
            let Some(manager) = manager.upgrade() else {
                break;
            };
            let scope = next_scope(&focus, last_full_pass.elapsed());
            let full = matches!(scope, PassScope::Every);
            if full {
                last_full_pass = tokio::time::Instant::now();
            }
            let listeners: Vec<ListenerInfo> = manager
                .get_active_listeners()
                .await
                .into_iter()
                .filter(|listener| match &scope {
                    PassScope::Every => true,
                    PassScope::Only(silent) => silent.contains(&listener.connection_point_id),
                })
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
            let (after_pass, next_focus) = unanswered.record(&pass, full);
            focus = next_focus;
            delay = next_delay(after_pass, last_full_pass.elapsed());
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
    if unanswered && matches!(repair, AccountRepair::RestartListener) {
        return AccountCheck::UnansweredAndRestarted(repaired);
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
            AccountCheck::UnansweredAndRestarted(Err("Connection point 'cp-1' not found".into())),
            "a silent probe restarts the listener once one is due, and stays counted as silence"
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
        probes.record(&pass(&[("cp-1", AccountCheck::Unanswered)]), true);
        assert!(probes.restart_due("cp-1"), "the second in a row is not");

        probes.record(&pass(&[("cp-1", AccountCheck::Healthy)]), true);
        assert!(!probes.restart_due("cp-1"), "an answered probe starts the count again");

        probes.record(&pass(&[("cp-1", AccountCheck::Unanswered)]), true);
        assert!(probes.restart_due("cp-1"));
        probes.record(&pass(&[("cp-1", AccountCheck::UnansweredAndRestarted(Ok(())))]), true);
        assert!(
            !probes.restart_due("cp-1"),
            "the restart is counted as silence, so the next restart waits for the fourth probe"
        );

        probes.record(&pass(&[("cp-1", AccountCheck::Repaired(AccountRepair::RestartListener, Ok(())))]), true);
        assert!(!probes.restart_due("cp-1"), "a refused probe is an answer, so the count starts again");
    }

    /// Feeds the tracker what the watch really produces for a mediator that
    /// says nothing: a restart on the passes where one is due, silence on the
    /// rest. Recording `Unanswered` on a restart pass would not exercise the
    /// backoff, since the loop never produces that.
    #[test]
    fn a_mediator_that_stays_silent_is_restarted_ever_more_slowly() {
        let mut probes = UnansweredProbes::default();
        let mut restarted_on = Vec::new();

        for probe in 1..=16 {
            let check = if probes.restart_due("cp-1") {
                restarted_on.push(probe);
                AccountCheck::UnansweredAndRestarted(Ok(()))
            } else {
                AccountCheck::Unanswered
            };
            let (delay, focus) = probes.record(&pass(&[("cp-1", check)]), true);
            assert_eq!(delay, UNANSWERED_RECHECK_INTERVAL, "silence keeps the faster re-probe");
            assert!(focus.contains("cp-1"), "a restarted listener is probed again to confirm it recovered");
        }

        assert_eq!(restarted_on, [2, 4, 8, 16], "restarts back off instead of repeating every other pass");
    }

    /// A listener restarted for silence is often still re-authenticating when
    /// the next pass runs, so that pass skips it. A skipped pass must not
    /// count as an answer, or the backoff starts over and the listener is
    /// restarted on a fixed short cycle.
    #[test]
    fn a_pass_that_skipped_a_listener_does_not_reset_its_backoff() {
        let mut probes = UnansweredProbes::default();
        let mut restarted_on_probe = Vec::new();
        let mut probe = 0;
        let mut reauthenticating = false;

        for _ in 0..40 {
            let check = if reauthenticating {
                reauthenticating = false;
                AccountCheck::Skipped
            } else {
                probe += 1;
                if probes.restart_due("cp-1") {
                    restarted_on_probe.push(probe);
                    reauthenticating = true;
                    AccountCheck::UnansweredAndRestarted(Err("listener restart timed out".into()))
                } else {
                    AccountCheck::Unanswered
                }
            };
            probes.record(&pass(&[("cp-1", check)]), true);
        }

        assert_eq!(restarted_on_probe, [2, 4, 8, 16, 32], "the backoff survives the skipped passes between restarts");
    }

    #[test]
    fn an_answer_after_a_restart_starts_the_backoff_again() {
        let mut probes = UnansweredProbes::default();
        probes.record(&pass(&[("cp-1", AccountCheck::Unanswered)]), true);
        probes.record(&pass(&[("cp-1", AccountCheck::UnansweredAndRestarted(Ok(())))]), true);

        let (delay, focus) = probes.record(&pass(&[("cp-1", AccountCheck::Healthy)]), true);
        assert_eq!(delay, ACCOUNT_CHECK_INTERVAL, "a recovered listener goes back to the usual cadence");
        assert!(focus.is_empty());
        assert!(!probes.restart_due("cp-1"), "the next silent probe is tolerated again");
    }

    #[test]
    fn only_the_listeners_that_went_unanswered_are_probed_again_sooner() {
        let mut probes = UnansweredProbes::default();

        let (delay, focus) =
            probes.record(&pass(&[("cp-1", AccountCheck::Healthy), ("cp-2", AccountCheck::Unreadable)]), true);
        assert_eq!(delay, ACCOUNT_CHECK_INTERVAL, "an answered refusal keeps the usual cadence");
        assert!(focus.is_empty(), "every listener is probed on the next pass");

        let (delay, focus) =
            probes.record(&pass(&[("cp-1", AccountCheck::Healthy), ("cp-2", AccountCheck::Unanswered)]), true);
        assert_eq!(delay, UNANSWERED_RECHECK_INTERVAL);
        assert_eq!(focus, std::collections::HashSet::from(["cp-2".to_string()]), "only the silent one");
        assert!(UNANSWERED_RECHECK_INTERVAL < ACCOUNT_CHECK_INTERVAL);
    }

    /// Everything the watch promises, on one run with the mix that broke each
    /// promise in turn: a mediator that never answers, a healthy one, and a
    /// listener that is down the whole time.
    #[test]
    fn a_silent_mediator_starves_nothing_and_still_backs_off() {
        let mut probes = UnansweredProbes::default();
        let mut focus = std::collections::HashSet::new();
        let mut since_full_pass = Duration::ZERO;
        let mut delay = ACCOUNT_CHECK_INTERVAL;
        let mut elapsed = Duration::ZERO;

        let mut healthy_checks = Vec::new();
        let mut silent_probe = 0;
        let mut restarted_on_probe = Vec::new();
        let mut reauthenticating = false;

        for _ in 0..40 {
            elapsed += delay;
            since_full_pass += delay;
            let scope = next_scope(&focus, since_full_pass);
            let full = scope == PassScope::Every;
            if full {
                since_full_pass = Duration::ZERO;
            }

            let silent_check = if reauthenticating {
                reauthenticating = false;
                AccountCheck::Skipped
            } else {
                silent_probe += 1;
                if probes.restart_due("cp-silent") {
                    restarted_on_probe.push(silent_probe);
                    reauthenticating = true;
                    AccountCheck::UnansweredAndRestarted(Err("listener restart timed out".into()))
                } else {
                    AccountCheck::Unanswered
                }
            };
            let mut outcomes = vec![("cp-silent".to_string(), silent_check)];
            if full {
                healthy_checks.push(elapsed);
                outcomes.push(("cp-healthy".to_string(), AccountCheck::Healthy));
                outcomes.push(("cp-down".to_string(), AccountCheck::Skipped));
            }

            let (after_pass, next_focus) = probes.record(&outcomes, full);
            focus = next_focus;
            delay = next_delay(after_pass, since_full_pass);
        }

        let longest_wait = healthy_checks
            .windows(2)
            .map(|pair| pair[1] - pair[0])
            .max()
            .expect("the healthy listener is checked more than once");
        assert!(
            longest_wait <= ACCOUNT_CHECK_INTERVAL,
            "a healthy listener waited {longest_wait:?} while another mediator stayed silent"
        );
        assert_eq!(restarted_on_probe, [2, 4, 8, 16, 32], "the silent one still backs off");
        assert!(!probes.restart_due("cp-down"), "a listener that is never connected is never restarted for silence");
    }

    #[test]
    fn a_listener_that_is_gone_is_forgotten() {
        let mut probes = UnansweredProbes::default();
        probes.record(&pass(&[("cp-1", AccountCheck::Unanswered)]), true);
        assert!(probes.restart_due("cp-1"));

        probes.record(&pass(&[("cp-2", AccountCheck::Healthy)]), true);
        assert!(!probes.restart_due("cp-1"), "a listener no longer checked keeps no count");
    }

    #[test]
    fn a_narrowed_pass_keeps_the_counts_of_the_listeners_it_did_not_visit() {
        let mut probes = UnansweredProbes::default();
        probes.record(&pass(&[("cp-one", AccountCheck::Unanswered), ("cp-two", AccountCheck::Unanswered)]), true);

        probes.record(&pass(&[("cp-one", AccountCheck::Unanswered)]), false);
        assert!(
            probes.restart_due("cp-two"),
            "a listener the narrowed pass did not visit keeps the silence already counted against it"
        );

        probes.record(&pass(&[("cp-two", AccountCheck::Healthy)]), true);
        assert!(!probes.restart_due("cp-two"), "its first answer still starts the count again");
    }

    #[test]
    fn a_pass_never_waits_past_the_next_full_sweep() {
        assert_eq!(
            next_delay(ACCOUNT_CHECK_INTERVAL, Duration::ZERO),
            ACCOUNT_CHECK_INTERVAL,
            "a full pass starts the interval again"
        );
        assert_eq!(
            next_delay(UNANSWERED_RECHECK_INTERVAL, Duration::from_secs(10)),
            UNANSWERED_RECHECK_INTERVAL,
            "the fast re-probe runs as usual inside the interval"
        );
        assert_eq!(
            next_delay(ACCOUNT_CHECK_INTERVAL, Duration::from_secs(20)),
            Duration::from_secs(10),
            "a pass that ends with nothing silent waits only for the sweep that is already due"
        );
        assert_eq!(
            next_delay(ACCOUNT_CHECK_INTERVAL, ACCOUNT_CHECK_INTERVAL * 2),
            Duration::ZERO,
            "an overdue sweep runs at once"
        );
    }

    #[test]
    fn every_listener_is_visited_once_the_full_interval_has_passed() {
        let silent = std::collections::HashSet::from(["cp-silent".to_string()]);

        assert_eq!(
            next_scope(&std::collections::HashSet::new(), Duration::ZERO),
            PassScope::Every,
            "with nothing silent, every pass is a full one"
        );
        assert_eq!(
            next_scope(&silent, UNANSWERED_RECHECK_INTERVAL),
            PassScope::Only(silent.clone()),
            "the fast re-probe visits only the silent listeners"
        );
        assert_eq!(
            next_scope(&silent, ACCOUNT_CHECK_INTERVAL),
            PassScope::Every,
            "a mediator that never answers cannot hold up the rest beyond the usual interval"
        );
    }

    /// The case the fast re-probe must not starve: one listener whose mediator
    /// says nothing, one whose mediator is healthy.
    #[test]
    fn a_silent_listener_does_not_stop_the_others_being_checked() {
        let mut probes = UnansweredProbes::default();
        let mut focus = std::collections::HashSet::new();
        let mut since_full_pass = Duration::ZERO;
        let mut delay = ACCOUNT_CHECK_INTERVAL;
        let mut restarted_on = Vec::new();
        let mut elapsed = Duration::ZERO;
        let mut full_passes = Vec::new();

        for probe in 1..=24 {
            elapsed += delay;
            since_full_pass += delay;
            let scope = next_scope(&focus, since_full_pass);
            let full = scope == PassScope::Every;
            if full {
                since_full_pass = Duration::ZERO;
            }

            let mut outcomes = vec![(
                "cp-silent".to_string(),
                if probes.restart_due("cp-silent") {
                    restarted_on.push(probe);
                    AccountCheck::UnansweredAndRestarted(Ok(()))
                } else {
                    AccountCheck::Unanswered
                },
            )];
            if full {
                full_passes.push(elapsed);
                outcomes.push(("cp-healthy".to_string(), AccountCheck::Healthy));
            }
            (delay, focus) = probes.record(&outcomes, full);
        }

        let longest_gap = full_passes
            .windows(2)
            .map(|pair| pair[1] - pair[0])
            .max()
            .expect("more than one full pass");
        assert!(
            longest_gap <= ACCOUNT_CHECK_INTERVAL + UNANSWERED_RECHECK_INTERVAL,
            "the healthy listener waited {longest_gap:?} to be checked while the other stayed silent"
        );
        assert!(full_passes.len() >= 4, "it is checked repeatedly, not once: {full_passes:?}");
        assert_eq!(restarted_on, [2, 4, 8, 16], "and the silent one still backs off");
    }
}
