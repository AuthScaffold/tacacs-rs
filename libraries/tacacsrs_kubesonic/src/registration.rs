//! Optional atomic loopback-row registration, separate from read-only discovery.

use anyhow::Context;

use crate::environment::SourceSettings;

const KEY: &str = "TACPLUS_SERVER|127.0.0.1";

/// Owns only a loopback row that this instance successfully created.
pub struct LoopbackRegistration {
    source: SourceSettings,
    priority: u16,
    port: u16,
    owned: bool,
}

impl LoopbackRegistration {
    /// Creates a writer for an enabled, validated loopback proxy.
    #[must_use]
    pub fn new(source: SourceSettings, priority: u16, port: u16) -> Self {
        Self {
            source,
            priority,
            port,
            owned: false,
        }
    }

    async fn command<T: redis::FromRedisValue>(&self, command: &redis::Cmd) -> anyhow::Result<T> {
        let mut connection = self.source.connect().await?;
        tokio::time::timeout(self.source.command_timeout, command.query_async(&mut connection))
            .await
            .context("Loopback registration command timed out")?
            .context("Loopback registration command failed")
    }

    /// Removes the startup row under the explicitly enabled legacy policy.
    ///
    /// # Errors
    /// Returns an error when ConfigDB cannot complete the deletion.
    pub async fn remove_stale(&self) -> anyhow::Result<()> {
        let removed: u64 = self.command(redis::cmd("DEL").arg(KEY)).await?;
        if removed > 0 {
            log::warn!("Removed startup loopback row under the enabled registration policy");
        }
        Ok(())
    }

    /// Registers or repairs a missing row only after local readiness.
    ///
    /// # Errors
    /// Returns an error when ConfigDB cannot complete the comparison.
    pub async fn reconcile(&mut self, ready: bool) -> anyhow::Result<()> {
        let exists: bool = self.command(redis::cmd("EXISTS").arg(KEY)).await?;
        if exists {
            return Ok(());
        }
        self.owned = false;
        if ready {
            self.owned = self
                .command(
                    redis::cmd("EVAL")
                        .arg(REGISTER)
                        .arg(1)
                        .arg(KEY)
                        .arg(self.port)
                        .arg(self.priority),
                )
                .await?;
            if self.owned {
                log::info!("Registered ready loopback proxy");
            } else {
                log::warn!("Another writer created the loopback row; preserving it");
            }
        }
        Ok(())
    }

    /// Removes an owned row only while its complete contents remain unchanged.
    ///
    /// # Errors
    /// Returns an error when ConfigDB cannot complete cleanup.
    pub async fn cleanup(&mut self) -> anyhow::Result<()> {
        if self.owned {
            let removed: bool = self
                .command(
                    redis::cmd("EVAL")
                        .arg(CLEANUP)
                        .arg(1)
                        .arg(KEY)
                        .arg(self.port)
                        .arg(self.priority),
                )
                .await?;
            if !removed {
                log::warn!("Owned loopback row is absent or changed; preserving external state");
            }
            self.owned = false;
        }
        Ok(())
    }
}

const REGISTER: &str = r"
if redis.call('EXISTS', KEYS[1]) ~= 0 then return 0 end
redis.call('HSET', KEYS[1], 'tcp_port', ARGV[1], 'priority', ARGV[2])
return 1
";

const CLEANUP: &str = r"
if redis.call('TYPE', KEYS[1]).ok ~= 'hash' then return 0 end
if redis.call('HLEN', KEYS[1]) ~= 2 then return 0 end
if redis.call('HGET', KEYS[1], 'tcp_port') ~= ARGV[1] then return 0 end
if redis.call('HGET', KEYS[1], 'priority') ~= ARGV[2] then return 0 end
return redis.call('DEL', KEYS[1])
";
