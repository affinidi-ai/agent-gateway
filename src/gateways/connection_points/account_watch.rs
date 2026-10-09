//! Checks that the mediator still holds each Connection Point's account.
//!
//! The mediator can lose accounts while the WebSocket stays open, for example
//! when its store is flushed or fails over. It recreates an account only when
//! that account sends, and refuses delivery to a missing one, so a Connection
//! Point that only receives would stay unreachable. Every active listener's
//! own account is therefore probed on an interval and repaired.

use std::sync::{Arc, Weak};
use std::time::Duration;

use affinidi_messaging_sdk::errors::ATMError;
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
    Probed(AccountRepair),
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
        loop {
            interval.tick().await;
            let Some(manager) = manager.upgrade() else {
                break;
            };
            for listener in manager
                .get_active_listeners()
                .await
            {
                check_listener(&manager, &listener).await;
            }
        }
    });
}

async fn check_listener(
    manager: &ConnectionPointListenerManager,
    listener: &ListenerInfo,
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

    let probe = probe_own_account(&listener.client).await;
    let repair = account_repair(&probe);
    match repair {
        AccountRepair::Nothing if !matches!(probe, Ok(Ok(_))) => {
            debug!(connection_point = %listener.name, "Could not read the mediator account; leaving the listener as it is");
        }
        AccountRepair::Nothing => {}
        AccountRepair::RestartListener => {
            warn!(
                connection_point = %listener.name,
                "The mediator no longer has this Connection Point's account; restarting it to re-authenticate and re-register"
            );
            if let Err(error) = manager
                .restart_listener_if_current(
                    &listener.connection_point_id,
                    &listener.instance_id,
                    LISTENER_RESTART_TIMEOUT,
                )
                .await
            {
                warn!(connection_point = %listener.name, "Connection Point restart failed: {error}");
            }
        }
        AccountRepair::ReopenReceiveList => {
            warn!(
                connection_point = %listener.name,
                "The mediator account's receive list is closed; re-opening it"
            );
            if let Err(error) =
                set_acl_to_allow_everything_and_more(listener.client.atm(), Arc::clone(listener.client.profile())).await
            {
                warn!(connection_point = %listener.name, "Re-opening the receive list failed: {error}");
            }
        }
    }
    AccountCheck::Probed(repair)
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

    #[tokio::test]
    async fn a_listener_that_is_not_connected_is_not_probed() {
        let root = tempfile::TempDir::new().unwrap();
        let (manager, _issuer_dir) = crate::gateways::test_helpers::test_listener_manager(root.path()).await;
        let listener = crate::gateways::test_helpers::test_listener("reconnecting").await;
        manager
            .register_test_listener(listener.clone())
            .await;

        for status in [ConnectionStatus::Reconnecting, ConnectionStatus::Failed] {
            listener
                .metrics
                .write()
                .await
                .status = status;
            assert_eq!(check_listener(&manager, &listener).await, AccountCheck::Skipped);
        }
    }
}
