//! Typed health groups backed by the `health-checks` package.

use std::collections::HashSet;
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Duration;

use health_checks::{
    HealthCheck, HealthCheckRegistration, HealthCheckService, HealthChecks, HealthStatus,
};

use crate::ShutdownSignal;

/// Delay between two assessments while a consumer waits for a healthy group.
pub const POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Time limit for one check in one assessment.
///
/// The limit applies to checks that yield. It cannot stop blocking code.
pub const CHECK_TIMEOUT: Duration = Duration::from_secs(2);

/// Policy for a group with no members.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EmptyGroup {
    /// Bootstrap fails when an enabled consumer requires the group.
    Reject,
    /// An empty group is healthy and runs no checks.
    Allow,
}

/// Identifies one typed health group.
///
/// The consumer of a group usually defines its group type.
pub trait HealthGroupKind: Send + Sync + 'static {
    /// Stable, secret-free diagnostic name.
    const NAME: &'static str;
    /// Policy for a group with no members.
    const EMPTY: EmptyGroup;
}

/// A named check that contributes to group `G`.
///
/// A check must be cancellation-safe, must not spawn detached work, and must
/// return secret-free results.
pub trait HealthMember<G: HealthGroupKind>: HealthCheck {
    /// Returns a stable, secret-free member name that is unique in `G`.
    fn name(&self) -> &'static str;
}

/// Makes sure that member names are valid for group `G`.
///
/// # Errors
/// Returns an error for an empty name, a duplicate name, or an empty group
/// that `G` rejects.
pub fn validate_member_names<G: HealthGroupKind>(names: &[&'static str]) -> anyhow::Result<()> {
    anyhow::ensure!(
        !names.is_empty() || G::EMPTY == EmptyGroup::Allow,
        "Health group {} requires at least one member",
        G::NAME
    );
    let mut seen = HashSet::new();
    for name in names {
        anyhow::ensure!(
            !name.trim().is_empty(),
            "Health group {} has a member with an empty name",
            G::NAME
        );
        anyhow::ensure!(
            seen.insert(*name),
            "Health group {} has more than one member named {name}",
            G::NAME
        );
    }
    Ok(())
}

/// The secret-free result of one group assessment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupAssessment {
    /// The worst member status. An empty group is healthy.
    pub status: HealthStatus,
    /// Names of members that did not report a healthy status.
    pub failed: Vec<&'static str>,
}

impl GroupAssessment {
    /// Returns `true` when every member reported a healthy status.
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.status == HealthStatus::Healthy
    }
}

/// Aggregates the checks of group `G`.
pub struct HealthGroup<G> {
    checks: Option<HealthCheckService>,
    members: Vec<&'static str>,
    group: PhantomData<fn() -> G>,
}

impl<G: HealthGroupKind> HealthGroup<G> {
    /// Builds a group from its members without running a check.
    ///
    /// # Errors
    /// Returns the [`validate_member_names`] errors.
    pub fn new(members: Vec<Arc<dyn HealthMember<G>>>) -> anyhow::Result<Self> {
        let names: Vec<_> = members.iter().map(|member| member.name()).collect();
        validate_member_names::<G>(&names)?;
        let checks = (!members.is_empty()).then(|| {
            members
                .into_iter()
                .fold(HealthChecks::builder().default_timeout(CHECK_TIMEOUT), |checks, member| {
                    let name = member.name();
                    let check: Arc<dyn HealthCheck> = member;
                    checks.add(HealthCheckRegistration::from_arc(name, check))
                })
                .build()
        });
        Ok(Self {
            checks,
            members: names,
            group: PhantomData,
        })
    }

    /// Returns the member names in registration order.
    #[must_use]
    pub fn member_names(&self) -> &[&'static str] {
        &self.members
    }

    /// Runs one bounded assessment of all members.
    ///
    /// Dropping the future cancels the checks in progress.
    pub async fn assess(&self) -> GroupAssessment {
        let Some(checks) = &self.checks else {
            return GroupAssessment {
                status: HealthStatus::Healthy,
                failed: Vec::new(),
            };
        };
        let report = checks.check_health().await;
        let failed = self
            .members
            .iter()
            .copied()
            .filter(|name| {
                report
                    .entries
                    .get(*name)
                    .is_none_or(|entry| entry.status != HealthStatus::Healthy)
            })
            .collect();
        GroupAssessment {
            status: report.status,
            failed,
        }
    }

    /// Waits until the group is healthy.
    ///
    /// Returns `false` when shutdown occurs first. A shutdown request also
    /// cancels the assessment in progress.
    pub async fn wait_until_healthy(&self, shutdown: &ShutdownSignal) -> bool {
        loop {
            let assessment = tokio::select! {
                biased;
                () = shutdown.requested() => return false,
                assessment = self.assess() => assessment,
            };
            if assessment.is_healthy() {
                return true;
            }
            tokio::select! {
                biased;
                () = shutdown.requested() => return false,
                () = tokio::time::sleep(POLL_INTERVAL) => {}
            }
        }
    }
}

/// The group for checks that only report the health of their component.
///
/// No component waits for this group. Its members appear only in the
/// [`HealthRegistry`], for example in the health details of the agent.
pub struct ComponentHealth;

impl HealthGroupKind for ComponentHealth {
    const NAME: &'static str = "component";
    const EMPTY: EmptyGroup = EmptyGroup::Allow;
}

/// One check of one group, ready for the [`HealthRegistry`].
pub struct HealthRegistration {
    group: &'static str,
    name: &'static str,
    check: Arc<dyn HealthCheck>,
}

impl HealthRegistration {
    /// Wraps a member of group `G`.
    #[must_use]
    pub fn new<G: HealthGroupKind>(member: Arc<dyn HealthMember<G>>) -> Self {
        let name = member.name();
        let check: Arc<dyn HealthCheck> = member;
        Self {
            group: G::NAME,
            name,
            check,
        }
    }
}

/// The secret-free result of one check in the [`HealthRegistry`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HealthEntry {
    /// The name of the group of the check.
    pub group: &'static str,
    /// The name of the check. The name is unique in its group.
    pub name: &'static str,
    /// The status that the check reported.
    pub status: HealthStatus,
    /// The description that the check reported.
    ///
    /// When the check returns an error or panics, this value is a fixed text.
    /// The text of the error does not appear.
    pub description: Option<String>,
    /// The time that the check used.
    pub duration: Duration,
}

/// The fixed description of a check that returned an error or panicked.
pub const FAILED_CHECK_DESCRIPTION: &str = "The check failed with an error.";

/// Contains every health check of the application.
///
/// The registry has the same function as `HealthCheckService` in
/// `Microsoft.Extensions.Diagnostics.HealthChecks`. Each check has its group
/// name as a tag. A consumer can run all checks without a list of the
/// components that supplied them.
pub struct HealthRegistry {
    checks: Option<HealthCheckService>,
    entries: Vec<(&'static str, &'static str, String)>,
}

impl HealthRegistry {
    /// Builds a registry without running a check.
    ///
    /// # Errors
    /// Returns an error for an empty name or for two checks with the same
    /// group and name.
    pub fn new(registrations: Vec<HealthRegistration>) -> anyhow::Result<Self> {
        let mut entries = Vec::with_capacity(registrations.len());
        let mut builder = HealthChecks::builder().default_timeout(CHECK_TIMEOUT);
        for registration in registrations {
            let HealthRegistration { group, name, check } = registration;
            anyhow::ensure!(
                !group.trim().is_empty() && !name.trim().is_empty(),
                "A health check registration has an empty group or name"
            );
            let key = format!("{group}/{name}");
            anyhow::ensure!(
                entries.iter().all(|(_, _, existing)| *existing != key),
                "Health group {group} has more than one check named {name}"
            );
            builder =
                builder.add(HealthCheckRegistration::from_arc(key.clone(), check).tags([group]));
            entries.push((group, name, key));
        }
        Ok(Self {
            checks: (!entries.is_empty()).then(|| builder.build()),
            entries,
        })
    }

    /// Returns the group and name of each check in registration order.
    pub fn checks(&self) -> impl Iterator<Item = (&'static str, &'static str)> + '_ {
        self.entries.iter().map(|(group, name, _)| (*group, *name))
    }

    /// Runs all checks at the same time and returns one entry for each check.
    ///
    /// Each check has the [`CHECK_TIMEOUT`] limit. The entries are in
    /// registration order. Dropping the future cancels the checks in progress.
    pub async fn check_all(&self) -> Vec<HealthEntry> {
        let Some(checks) = &self.checks else {
            return Vec::new();
        };
        let mut report = checks.check_health().await;
        self.entries
            .iter()
            .map(|(group, name, key)| match report.entries.swap_remove(key) {
                Some(entry) => HealthEntry {
                    group,
                    name,
                    status: entry.status,
                    description: if entry.exception.is_some() {
                        Some(FAILED_CHECK_DESCRIPTION.to_owned())
                    } else {
                        entry.description
                    },
                    duration: entry.duration,
                },
                None => HealthEntry {
                    group,
                    name,
                    status: HealthStatus::Unhealthy,
                    description: Some(FAILED_CHECK_DESCRIPTION.to_owned()),
                    duration: Duration::ZERO,
                },
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use async_trait::async_trait;
    use health_checks::{BoxError, HealthCheckContext, HealthCheckResult};

    use super::*;
    use crate::ShutdownRequester;

    struct Required;
    impl HealthGroupKind for Required {
        const NAME: &'static str = "required";
        const EMPTY: EmptyGroup = EmptyGroup::Reject;
    }

    struct Optional;
    impl HealthGroupKind for Optional {
        const NAME: &'static str = "optional";
        const EMPTY: EmptyGroup = EmptyGroup::Allow;
    }

    enum Behavior {
        Flag(Arc<AtomicBool>),
        Secret,
        Pending(Arc<AtomicUsize>),
    }

    struct Member(&'static str, Behavior);

    #[async_trait]
    impl HealthCheck for Member {
        async fn check(&self, _: &HealthCheckContext) -> Result<HealthCheckResult, BoxError> {
            match &self.1 {
                Behavior::Flag(flag) if flag.load(Ordering::Acquire) => {
                    Ok(HealthCheckResult::healthy())
                }
                Behavior::Flag(_) => Ok(HealthCheckResult::unhealthy()),
                Behavior::Secret => Err("password=sentinel-secret".into()),
                Behavior::Pending(started) => {
                    started.fetch_add(1, Ordering::AcqRel);
                    std::future::pending().await
                }
            }
        }
    }

    impl<G: HealthGroupKind> HealthMember<G> for Member {
        fn name(&self) -> &'static str {
            self.0
        }
    }

    fn member<G: HealthGroupKind>(
        name: &'static str,
        behavior: Behavior,
    ) -> Arc<dyn HealthMember<G>> {
        Arc::new(Member(name, behavior))
    }

    #[tokio::test]
    async fn empty_group_policy_and_duplicate_names_are_enforced() {
        assert!(HealthGroup::<Required>::new(Vec::new()).is_err());
        let optional = HealthGroup::<Optional>::new(Vec::new()).unwrap();
        assert!(optional.assess().await.is_healthy());
        assert!(
            optional
                .wait_until_healthy(&ShutdownRequester::new().signal())
                .await
        );

        let flag = Arc::new(AtomicBool::new(true));
        let duplicate = HealthGroup::<Required>::new(vec![
            member("same", Behavior::Flag(flag.clone())),
            member("same", Behavior::Flag(flag)),
        ]);
        assert!(duplicate.is_err());
        assert!(validate_member_names::<Required>(&[" "]).is_err());
    }

    #[tokio::test]
    async fn assessment_names_failed_members_without_error_text() {
        let flag = Arc::new(AtomicBool::new(true));
        let group = HealthGroup::<Required>::new(vec![
            member("ready", Behavior::Flag(flag)),
            member("secret", Behavior::Secret),
        ])
        .unwrap();
        let assessment = group.assess().await;
        assert_eq!(assessment.status, HealthStatus::Unhealthy);
        assert_eq!(assessment.failed, vec!["secret"]);
        assert!(!format!("{assessment:?}").contains("sentinel"));
    }

    #[tokio::test(start_paused = true)]
    async fn timeout_fails_a_pending_check_and_shutdown_cancels_the_wait() {
        let started = Arc::new(AtomicUsize::new(0));
        let group = HealthGroup::<Required>::new(vec![member(
            "pending",
            Behavior::Pending(started.clone()),
        )])
        .unwrap();
        let assessment = group.assess().await;
        assert_eq!(assessment.failed, vec!["pending"]);

        let requester = ShutdownRequester::new();
        let signal = requester.signal();
        let wait = group.wait_until_healthy(&signal);
        tokio::pin!(wait);
        tokio::select! {
            biased;
            _ = &mut wait => panic!("An unhealthy group must keep waiting"),
            () = tokio::time::sleep(CHECK_TIMEOUT + POLL_INTERVAL + CHECK_TIMEOUT / 2) => {}
        }
        assert_eq!(started.load(Ordering::Acquire), 3);
        requester.request();
        assert!(!wait.await);
    }

    #[tokio::test(start_paused = true)]
    async fn registry_reports_every_group_without_error_text() {
        let flag = Arc::new(AtomicBool::new(true));
        let started = Arc::new(AtomicUsize::new(0));
        let registry = HealthRegistry::new(vec![
            HealthRegistration::new(member::<Required>("ready", Behavior::Flag(flag.clone()))),
            HealthRegistration::new(member::<Optional>("ready", Behavior::Flag(flag))),
            HealthRegistration::new(member::<Optional>("secret", Behavior::Secret)),
            HealthRegistration::new(member::<Optional>("pending", Behavior::Pending(started))),
        ])
        .unwrap();
        assert_eq!(
            registry.checks().collect::<Vec<_>>(),
            [
                ("required", "ready"),
                ("optional", "ready"),
                ("optional", "secret"),
                ("optional", "pending")
            ]
        );

        let entries = registry.check_all().await;
        let statuses: Vec<_> = entries
            .iter()
            .map(|entry| (entry.group, entry.name, entry.status))
            .collect();
        assert_eq!(
            statuses,
            [
                ("required", "ready", HealthStatus::Healthy),
                ("optional", "ready", HealthStatus::Healthy),
                ("optional", "secret", HealthStatus::Unhealthy),
                ("optional", "pending", HealthStatus::Unhealthy),
            ]
        );
        assert_eq!(entries[2].description.as_deref(), Some(FAILED_CHECK_DESCRIPTION));
        assert!(!format!("{entries:?}").contains("sentinel"));
    }

    #[tokio::test]
    async fn registry_rejects_a_duplicate_check_and_allows_no_checks() {
        let flag = Arc::new(AtomicBool::new(true));
        let duplicate = HealthRegistry::new(vec![
            HealthRegistration::new(member::<Optional>("same", Behavior::Flag(flag.clone()))),
            HealthRegistration::new(member::<Optional>("same", Behavior::Flag(flag))),
        ]);
        assert!(duplicate.is_err());
        let empty = HealthRegistry::new(Vec::new()).unwrap();
        assert!(empty.check_all().await.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn wait_returns_after_a_member_becomes_healthy() {
        let flag = Arc::new(AtomicBool::new(false));
        let group =
            HealthGroup::<Required>::new(vec![member("flag", Behavior::Flag(flag.clone()))])
                .unwrap();
        let signal = ShutdownRequester::new().signal();
        let wait = group.wait_until_healthy(&signal);
        tokio::pin!(wait);
        tokio::select! {
            biased;
            _ = &mut wait => panic!("An unhealthy group must keep waiting"),
            () = tokio::time::sleep(POLL_INTERVAL / 2) => {}
        }
        flag.store(true, Ordering::Release);
        assert!(wait.await);
    }
}
