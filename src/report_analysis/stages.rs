//! A common presentation of execution, collection and existing scanner statuses.
use super::NormalizedRun;
use crate::detection::Status;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StageResult {
    pub stage: String,
    pub status: Status,
    pub target: Option<String>,
    pub warnings: Vec<String>,
}
fn execution_status(value: &Value) -> Status {
    if value.get("timed_out").and_then(Value::as_bool) == Some(true) {
        Status::TimedOut
    } else {
        match value.get("exit_code").and_then(Value::as_i64) {
            Some(0) => Status::Completed,
            Some(_) => Status::Failed,
            None => Status::Unavailable,
        }
    }
}
fn cleanup_status(value: &Value) -> Status {
    match (
        value.get("attempted").and_then(Value::as_bool),
        value.get("success").and_then(Value::as_bool),
    ) {
        (Some(false), _) => Status::Skipped,
        (Some(true), Some(true))
            if value
                .get("leftover_resources")
                .and_then(Value::as_array)
                .is_none_or(Vec::is_empty) =>
        {
            Status::Completed
        }
        (Some(true), _) => Status::Failed,
        _ => Status::Unavailable,
    }
}
pub fn summarize(run: &NormalizedRun) -> Vec<StageResult> {
    let host = run.raw.get("host_report").and_then(|v| v.get("result"));
    let execution = host.unwrap_or(&run.execution);
    let cleanup = host.and_then(|v| v.get("cleanup")).unwrap_or(&Value::Null);
    let mut result = vec![
        StageResult {
            stage: "execution".into(),
            status: execution_status(execution),
            target: None,
            warnings: vec![],
        },
        StageResult {
            stage: "cleanup".into(),
            status: cleanup_status(cleanup),
            target: None,
            warnings: vec![],
        },
    ];
    for health in &run.capture_health {
        let warnings = health.coverage_warnings();
        let status = if !health.requested {
            Status::Skipped
        } else if !health.started {
            Status::Unavailable
        } else if !health.stopped || !health.provider_errors.is_empty() {
            Status::Failed
        } else if health.truncated || !warnings.is_empty() {
            Status::Partial
        } else {
            Status::Completed
        };
        result.push(StageResult {
            stage: health.channel.clone(),
            status,
            target: None,
            warnings,
        });
    }
    for scanner in &run.detection.stages {
        result.push(StageResult {
            stage: scanner.scanner.clone(),
            status: scanner.status,
            target: Some(scanner.target.clone()),
            warnings: scanner.warnings.iter().map(|w| w.message.clone()).collect(),
        });
    }
    for (name, config) in run.detection.effective_config.stages() {
        if !run.detection.stages.iter().any(|row| row.scanner == name) {
            result.push(StageResult {
                stage: name.into(),
                status: if config.enabled {
                    Status::Unavailable
                } else {
                    Status::Disabled
                },
                target: None,
                warnings: vec!["No scanner result was recorded for this stage.".into()],
            });
        }
    }
    result.push(StageResult {
        stage: "behavioral".into(),
        status: run.detection.behavioral_status,
        target: None,
        warnings: run
            .detection
            .warnings
            .iter()
            .map(|w| w.message.clone())
            .collect(),
    });
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn exit_zero_does_not_override_timeout_or_failed_cleanup() {
        assert_eq!(
            execution_status(&json!({"exit_code":0,"timed_out":true})),
            Status::TimedOut
        );
        assert_eq!(execution_status(&json!({"exit_code":0})), Status::Completed);
        assert_eq!(
            cleanup_status(&json!({"attempted":true,"success":false})),
            Status::Failed
        );
        assert_eq!(
            cleanup_status(&json!({"attempted":true,"success":true,"leftover_resources":["vm"]})),
            Status::Failed
        );
        assert_eq!(cleanup_status(&Value::Null), Status::Unavailable);
    }

    #[test]
    fn summary_preserves_host_cleanup_failure_and_missing_scanner_coverage() {
        let mut run: NormalizedRun = serde_json::from_str(include_str!(
            "../../tests/fixtures/detection/normalized.json"
        ))
        .unwrap();
        run.raw.insert("host_report".into(), json!({"result":{"exit_code":0,"timed_out":false,"cleanup":{"attempted":true,"success":false}}}));
        run.detection.stages.clear();
        run.detection.effective_config.yara.enabled = false;
        let results = summarize(&run);
        let status = |name: &str| results.iter().find(|r| r.stage == name).unwrap().status;
        assert_eq!(status("execution"), Status::Completed);
        assert_eq!(status("cleanup"), Status::Failed);
        assert_eq!(status("yara"), Status::Disabled);
        assert_eq!(status("pe"), Status::Unavailable);
    }
}
