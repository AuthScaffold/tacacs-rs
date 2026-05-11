use std::collections::BTreeMap;

use serde_json::Value;
use tonic::Status;

use crate::scenario::{CapturedIpcRequest, EmulatorResponse, EmulatorScenario, IpcRpc, RuleHitCount};

pub(crate) struct EmulatorState {
    scenario: EmulatorScenario,
    captured_requests: Vec<CapturedIpcRequest>,
    hit_counts: Vec<u64>,
}

impl EmulatorState {
    pub(crate) fn new(scenario: EmulatorScenario) -> Self {
        let hit_counts = vec![0; scenario.transactions.len()];
        Self {
            scenario,
            captured_requests: Vec::new(),
            hit_counts,
        }
    }

    pub(crate) fn captured_requests(&self) -> Vec<CapturedIpcRequest> {
        self.captured_requests.clone()
    }

    pub(crate) fn replace_scenario(&mut self, scenario: EmulatorScenario) {
        *self = Self::new(scenario);
    }

    pub(crate) fn reset(&mut self) {
        self.captured_requests.clear();
        self.hit_counts.fill(0);
    }

    pub(crate) fn rule_hit_counts(&self) -> Vec<RuleHitCount> {
        self.scenario
            .transactions
            .iter()
            .enumerate()
            .map(|(index, rule)| RuleHitCount {
                index,
                rpc: rule.rpc,
                hits: self.hit_counts[index],
            })
            .collect()
    }

    pub(crate) fn record_and_match(
        &mut self,
        rpc: IpcRpc,
        fields: &BTreeMap<String, Value>,
    ) -> Result<MatchedRule, Status> {
        self.captured_requests.push(CapturedIpcRequest {
            rpc,
            fields: fields.clone(),
        });
        let Some((index, rule)) = self
            .scenario
            .transactions
            .iter()
            .enumerate()
            .find(|(_, rule)| rule.rpc == rpc && rule.match_fields.matches(fields))
        else {
            let request_json = serde_json::to_string(fields).map_err(|error| {
                Status::internal(format!(
                    "Failed to encode unmatched IPC request for diagnostics: {error}"
                ))
            })?;
            return Err(Status::not_found(format!(
                "IPC emulator has no {rpc} transaction rule matching {request_json}"
            )));
        };
        self.hit_counts[index] += 1;
        Ok(MatchedRule {
            response: rule.respond.clone(),
            delay_ms: rule.delay_ms,
        })
    }
}

pub(crate) struct MatchedRule {
    pub(crate) response: EmulatorResponse,
    pub(crate) delay_ms: Option<u64>,
}
