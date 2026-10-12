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
use futures::StreamExt;
use tracing::{debug, warn};
use trust_tasks_rs::specs::messaging::account::get::v0_1::Account;

use super::ws_listener::{ConnectionPointListenerManager, ConnectionStatus, ListenerInfo};
use crate::comm::didcomm::client::DIDCommClient;
use crate::mediators::utils::set_acl_to_allow_everything_and_more;

const ACCOUNT_CHECK_INTERVAL: Duration = Duration::from_secs(30);

/// How long the mediator may take to return the Connection Point's account.
const ACCOUNT_PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// How long a restarted listener may take to re-authenticate and re-register.
const LISTENER_RESTART_TIMEOUT: Duration = Duration::from_secs(20);

/// How long the mediator may take to re-open a closed receive list.
const RECEIVE_LIST_REOPEN_TIMEOUT: Duration = Duration::from_secs(10);

/// How many listeners are checked at once.
const CONCURRENT_ACCOUNT_CHECKS: usize = 4;

/// The problem-report code a mediator answers with when it no longer has the
/// requesting account.
const ACCOUNT_NOT_FOUND_CODE: &str = "e.p.account.not_found";

pub(crate) type AccountProbe = Result<Result<Account, ATMError>, tokio::time::error::Elapsed>;

/// What a probe of the Connection Point's own mediator account calls for.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum AccountRepair {
    /// The account accepts messages, or it could not be read.
    Nothing,
    /// The mediator no longer has the account: restart the listener so it
    /// re-authenticates and re-registers.
    RestartListener,
    /// The account exists but its receive list is closed: re-open it.
    ReopenReceiveList,
}

/// What [`check_listener`] did with one listener.
#[derive(Debug, PartialEq, Eq)]
enum AccountCheck {
    /// The listener is not connected, so its mediator session is not probed.
    Skipped,
    /// The account could not be read, so nothing was changed.
    Unreadable,
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
        set_acl_to_allow_everything_and_more(listener.client.atm(), Arc::clone(listener.client.profile())).await
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

pub(crate) fn account_repair(probe: &AccountProbe) -> AccountRepair {
    match probe {
        Ok(Ok(account)) => {
            let receive_list_open = account
                .acl
                .access_list_mode
                .as_ref()
                .is_some_and(|mode| mode.to_string() == "explicitDeny");
            if receive_list_open {
                AccountRepair::Nothing
            } else {
                AccountRepair::ReopenReceiveList
            }
        }
        Ok(Err(error)) if is_account_not_found(error) => AccountRepair::RestartListener,
        Ok(Err(_)) | Err(_) => AccountRepair::Nothing,
    }
}

fn is_account_not_found(error: &ATMError) -> bool {
    matches!(error, ATMError::ProblemReport(code, _, _) if code == ACCOUNT_NOT_FOUND_CODE)
}

/// Probes every active listener's account on an interval until the manager
/// is dropped.
pub(crate) fn spawn(manager: Weak<ConnectionPointListenerManager>) {
    crate::observability::spawn_traced_task("connection_points.account_watch", async move {
        let mut interval =
            tokio::time::interval_at(tokio::time::Instant::now() + ACCOUNT_CHECK_INTERVAL, ACCOUNT_CHECK_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut unreadable = std::collections::HashMap::new();
        loop {
            interval.tick().await;
            let Some(manager) = manager.upgrade() else {
                break;
            };
            let checks = futures::stream::iter(
                manager
                    .get_active_listeners()
                    .await,
            )
            .map(|listener| {
                let manager = &manager;
                async move {
                    let check = check_listener(manager, &listener, &ListenerSession).await;
                    (listener, check)
                }
            })
            .buffer_unordered(CONCURRENT_ACCOUNT_CHECKS)
            .collect::<Vec<_>>()
            .await;
            let checked = checks
                .iter()
                .map(|(listener, _)| {
                    listener
                        .connection_point_id
                        .clone()
                })
                .collect::<std::collections::HashSet<_>>();
            unreadable.retain(|connection_point_id, _| checked.contains(connection_point_id));
            for (listener, check) in checks {
                let failures = unreadable
                    .entry(listener.connection_point_id)
                    .or_insert(0u32);
                *failures = match check {
                    AccountCheck::Unreadable => failures.saturating_add(1),
                    _ => 0,
                };
                if warns_of_unreadable_account(*failures) {
                    warn!(
                        connection_point = %listener.name,
                        consecutive_failures = *failures,
                        "The mediator account could not be read; missing accounts are not being repaired"
                    );
                }
            }
        }
    });
}

/// Whether the `consecutive`th failure in a row to read an account is logged
/// at `warn`: the second, then at doubling intervals.
fn warns_of_unreadable_account(consecutive: u32) -> bool {
    consecutive >= 2 && consecutive.is_power_of_two()
}

async fn check_listener(
    manager: &ConnectionPointListenerManager,
    listener: &ListenerInfo,
    mediator: &impl MediatorAccount,
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
    let repair = account_repair(&probe);
    let repaired = match repair {
        AccountRepair::Nothing if !matches!(probe, Ok(Ok(_))) => {
            debug!(connection_point = %listener.name, "Could not read the mediator account; leaving the listener as it is");
            return AccountCheck::Unreadable;
        }
        AccountRepair::Nothing => return AccountCheck::Healthy,
        AccountRepair::RestartListener => {
            warn!(
                connection_point = %listener.name,
                "The mediator no longer has this Connection Point's account; restarting it to re-authenticate and re-register"
            );
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

    #[test]
    fn account_not_found_is_recognised_only_from_its_problem_report() {
        let missing = ATMError::ProblemReport(ACCOUNT_NOT_FOUND_CODE.into(), "gone".into(), "false".into());
        assert!(is_account_not_found(&missing));

        let other_report = ATMError::ProblemReport("e.p.access_list.denied".into(), "denied".into(), "false".into());
        assert!(!is_account_not_found(&other_report));

        let transport = ATMError::TransportError("account.not_found".into());
        assert!(!is_account_not_found(&transport));

        let near_miss = ATMError::ProblemReport("e.p.account.not_found_else".into(), "other".into(), "false".into());
        assert!(!is_account_not_found(&near_miss));
    }

    #[tokio::test]
    async fn only_a_missing_account_restarts_the_listener() {
        let missing =
            probe_error(ATMError::ProblemReport(ACCOUNT_NOT_FOUND_CODE.into(), "gone".into(), "false".into()));
        assert_eq!(account_repair(&missing), AccountRepair::RestartListener);

        let other_report =
            probe_error(ATMError::ProblemReport("e.p.access_list.denied".into(), "denied".into(), "false".into()));
        assert_eq!(account_repair(&other_report), AccountRepair::Nothing);

        let near_miss =
            probe_error(ATMError::ProblemReport("e.p.account.not_found_else".into(), "other".into(), "false".into()));
        assert_eq!(account_repair(&near_miss), AccountRepair::Nothing);

        let transport = probe_error(ATMError::TransportError("connection reset".into()));
        assert_eq!(account_repair(&transport), AccountRepair::Nothing);

        let probe_timed_out: AccountProbe = Err(tokio::time::timeout(Duration::ZERO, std::future::pending::<()>())
            .await
            .unwrap_err());
        assert_eq!(account_repair(&probe_timed_out), AccountRepair::Nothing);
    }

    #[test]
    fn only_a_closed_receive_list_is_reopened() {
        assert_eq!(account_repair(&probed_account("explicitDeny")), AccountRepair::Nothing);
        assert_eq!(account_repair(&probed_account("explicitAllow")), AccountRepair::ReopenReceiveList);
    }

    /// A mediator that answers every probe with `probe`, and counts the
    /// receive-list re-openings, each taking `reopen_delay`.
    struct StubMediator {
        probe: fn() -> AccountProbe,
        reopen_delay: Duration,
        reopened: std::sync::atomic::AtomicUsize,
    }

    impl StubMediator {
        fn answering(probe: fn() -> AccountProbe) -> Self {
            Self {
                probe,
                reopen_delay: Duration::ZERO,
                reopened: Default::default(),
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
        probe_error(ATMError::ProblemReport(ACCOUNT_NOT_FOUND_CODE.into(), "gone".into(), "false".into()))
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
            assert_eq!(check_listener(&manager, &listener, &mediator).await, AccountCheck::Skipped);
        }
    }

    #[tokio::test]
    async fn an_open_account_is_left_alone_and_an_unreadable_one_is_reported() {
        let root = tempfile::TempDir::new().unwrap();
        let (manager, listener, _issuer_dir) = connected_listener(root.path(), "probed").await;

        let open = StubMediator::answering(|| probed_account("explicitDeny"));
        assert_eq!(check_listener(&manager, &listener, &open).await, AccountCheck::Healthy);
        assert_eq!(open.reopened(), 0);

        let unreachable = StubMediator::answering(|| probe_error(ATMError::TransportError("connection reset".into())));
        assert_eq!(check_listener(&manager, &listener, &unreachable).await, AccountCheck::Unreadable);
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
            check_listener(&manager, &listener, &closed).await,
            AccountCheck::Repaired(AccountRepair::ReopenReceiveList, Ok(()))
        );
        assert_eq!(closed.reopened(), 1);

        tokio::time::pause();
        let hanging = StubMediator {
            reopen_delay: RECEIVE_LIST_REOPEN_TIMEOUT * 2,
            ..StubMediator::answering(|| probed_account("explicitAllow"))
        };
        assert_eq!(
            check_listener(&manager, &listener, &hanging).await,
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
            check_listener(&manager, &listener, &mediator).await,
            AccountCheck::Repaired(AccountRepair::RestartListener, Err("Connection point 'cp-1' not found".into())),
            "the restart reads the Connection Point to start it again"
        );

        let replacement = crate::gateways::test_helpers::test_listener("replacement").await;
        manager
            .register_test_listener(replacement)
            .await;
        assert_eq!(
            check_listener(&manager, &listener, &mediator).await,
            AccountCheck::Repaired(AccountRepair::RestartListener, Ok(())),
            "a listener another caller replaced is kept"
        );
        assert_eq!(mediator.reopened(), 0);
    }

    #[test]
    fn repeated_unreadable_accounts_warn_at_doubling_intervals() {
        let warned = (0..=40)
            .filter(|failures| warns_of_unreadable_account(*failures))
            .collect::<Vec<_>>();
        assert_eq!(warned, [2, 4, 8, 16, 32]);
    }
}
