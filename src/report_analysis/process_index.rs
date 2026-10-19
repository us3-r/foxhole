use super::model::{Process, ProcessAssociation};
use std::collections::{BTreeMap, BTreeSet};
use std::{cell::Cell, io, rc::Rc};

const MAX_ASSOCIATION_IMAGE_BYTES: usize = 64 * 1024 * 1024;

/// One allocation budget for legacy and structured event associations. Charge
/// before cloning guest-controlled image text, never after allocating it.
#[derive(Clone)]
pub(super) struct AssociationBudget {
    used: Rc<Cell<usize>>,
    maximum: usize,
}

impl Default for AssociationBudget {
    fn default() -> Self {
        Self {
            used: Rc::new(Cell::new(0)),
            maximum: MAX_ASSOCIATION_IMAGE_BYTES,
        }
    }
}

impl AssociationBudget {
    pub fn charge(&self, bytes: usize) -> io::Result<()> {
        let total = self
            .used
            .get()
            .checked_add(bytes)
            .filter(|total| *total <= self.maximum);
        self.used.set(total.unwrap_or(usize::MAX));
        self.check()
    }

    pub fn check(&self) -> io::Result<()> {
        if self.used.get() > self.maximum {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "process association image byte budget exceeded; analysis is incomplete",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Candidate {
    observed: u64,
    pid: u32,
}

struct Interval {
    start: u64,
    end: u64,
    candidate: Candidate,
}

/// Winner changes for inclusive observation ranges. Each observation contributes
/// at most two ranges, so construction is O(N log N) and lookup is O(log N).
#[derive(Default)]
struct Timeline(Vec<(u64, Option<Candidate>)>);

impl Timeline {
    fn new(intervals: Vec<Interval>, prefer_latest: bool) -> Self {
        let mut events = Vec::with_capacity(intervals.len() * 2);
        for (id, interval) in intervals.iter().enumerate() {
            events.push((interval.start, id, true));
            if let Some(after) = interval.end.checked_add(1) {
                events.push((after, id, false));
            }
        }
        events.sort_unstable();
        let mut active = BTreeSet::new();
        let mut changes = Vec::new();
        let mut next = 0;
        while next < events.len() {
            let time = events[next].0;
            while next < events.len() && events[next].0 == time {
                let (_, id, add) = events[next];
                let candidate = intervals[id].candidate;
                let rank = if prefer_latest {
                    u64::MAX - candidate.observed
                } else {
                    candidate.observed
                };
                let key = (rank, candidate.pid, id);
                if add {
                    active.insert(key);
                } else {
                    active.remove(&key);
                }
                next += 1;
            }
            let winner = active.first().map(|&(_, _, id)| intervals[id].candidate);
            if changes.last().is_none_or(|&(_, old)| old != winner) {
                changes.push((time, winner));
            }
        }
        Self(changes)
    }

    fn at(&self, time: u64) -> Option<Candidate> {
        let end = self.0.partition_point(|&(start, _)| start <= time);
        end.checked_sub(1).and_then(|index| self.0[index].1)
    }
}

/// Shared by filesystem, registry and network normalization, including explicit
/// PID lookups. Never rescan process lifetimes for an individual event.
pub(super) struct ProcessIndex<'a> {
    pub budget: AssociationBudget,
    by_pid: BTreeMap<u32, &'a Process>,
    before: Timeline,
    after: Timeline,
    empty: Timeline,
}

impl<'a> ProcessIndex<'a> {
    pub fn new(processes: &'a [Process]) -> Self {
        let mut by_pid = BTreeMap::new();
        let mut before = Vec::new();
        let mut after = Vec::new();
        let mut empty = Vec::new();
        for process in processes {
            by_pid.entry(process.pid).or_insert(process);
            let start = process
                .observations
                .iter()
                .filter(|o| o.status != "terminated")
                .map(|o| o.observed_at_ms)
                .min()
                .unwrap_or(process.observed_at_ms);
            let end = process
                .observations
                .iter()
                .filter(|o| o.status == "terminated")
                .map(|o| o.observed_at_ms)
                .min()
                .unwrap_or(u64::MAX);
            if start > end {
                continue;
            }
            if process.observations.is_empty() {
                empty.push(Interval {
                    start,
                    end,
                    candidate: Candidate {
                        observed: 0,
                        pid: process.pid,
                    },
                });
            }
            for observation in &process.observations {
                let observed = observation.observed_at_ms;
                let candidate = Candidate {
                    observed,
                    pid: process.pid,
                };
                // Include all observations when measuring distance, even those
                // outside the process's inferred lifetime (legacy semantics).
                if observed <= end {
                    before.push(Interval {
                        start: start.max(observed),
                        end,
                        candidate,
                    });
                }
                if start <= observed {
                    after.push(Interval {
                        start,
                        end: end.min(observed),
                        candidate,
                    });
                }
            }
        }
        Self {
            budget: AssociationBudget::default(),
            by_pid,
            before: Timeline::new(before, true),
            after: Timeline::new(after, false),
            empty: Timeline::new(empty, false),
        }
    }

    pub fn associate(
        &self,
        explicit_pid: Option<u32>,
        time: u64,
        root_pid: u32,
    ) -> io::Result<ProcessAssociation> {
        if let Some(pid) = explicit_pid {
            return self.for_pid(pid, false, "explicit_pid");
        }
        let nearest = [self.before.at(time), self.after.at(time)]
            .into_iter()
            .flatten()
            .map(|c| (c.observed.abs_diff(time), c.pid))
            .chain(self.empty.at(time).map(|c| (u64::MAX, c.pid)))
            .min();
        match nearest {
            Some((_, pid)) => self.for_pid(pid, true, "nearest_process_lifetime"),
            None => self.for_pid(root_pid, true, "root_target_fallback"),
        }
    }

    fn for_pid(&self, pid: u32, inferred: bool, method: &str) -> io::Result<ProcessAssociation> {
        let process = self.by_pid.get(&pid);
        let image = process.map(|p| p.image.as_str()).unwrap_or("<unknown>");
        self.budget.charge(image.len())?;
        Ok(ProcessAssociation {
            pid,
            image: image.into(),
            parent_pid: process.and_then(|p| p.parent_pid),
            inferred,
            method: method.into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::model::ProcessObservation;
    use super::*;
    use serde_json::Value;

    fn process(pid: u32, observations: &[(u64, &str)]) -> Process {
        Process {
            pid,
            parent_pid: Some(1),
            image: format!("p{pid}.exe"),
            command_line: None,
            status: "observed".into(),
            observed_at_ms: 5,
            raw: Value::Null,
            observations: observations
                .iter()
                .map(|&(time, status)| ProcessObservation {
                    evidence_id: String::new(),
                    pid,
                    parent_pid: Some(1),
                    image: format!("p{pid}.exe"),
                    command_line: None,
                    status: status.into(),
                    observed_at_ms: time,
                    source: String::new(),
                    raw: Value::Null,
                })
                .collect(),
        }
    }

    fn reference(processes: &[Process], time: u64) -> Option<u32> {
        processes
            .iter()
            .filter(|p| {
                let start = p
                    .observations
                    .iter()
                    .filter(|o| o.status != "terminated")
                    .map(|o| o.observed_at_ms)
                    .min()
                    .unwrap_or(p.observed_at_ms);
                let end = p
                    .observations
                    .iter()
                    .filter(|o| o.status == "terminated")
                    .map(|o| o.observed_at_ms)
                    .min()
                    .unwrap_or(u64::MAX);
                start <= time && time <= end
            })
            .map(|p| {
                (
                    p.observations
                        .iter()
                        .map(|o| o.observed_at_ms.abs_diff(time))
                        .min()
                        .unwrap_or(u64::MAX),
                    p.pid,
                )
            })
            .min()
            .map(|(_, pid)| pid)
    }

    #[test]
    fn indexed_associations_match_the_reference_at_boundaries_and_reused_pids() {
        let mut processes = vec![
            process(
                30,
                &[(10, "observed"), (40, "terminated"), (80, "observed")],
            ),
            process(20, &[(10, "observed"), (40, "terminated")]),
            process(10, &[(0, "observed"), (u64::MAX, "terminated")]),
            process(50, &[(30, "observed"), (15, "terminated")]),
            process(60, &[]),
        ];
        // Deterministic varied intervals, including observations outside the lifetime.
        for pid in 70..170 {
            let start = (u64::from(pid) * 17) % 97;
            processes.push(process(
                pid,
                &[
                    (start, "observed"),
                    (start + 37, "terminated"),
                    (start + 70, "observed"),
                ],
            ));
        }
        processes.reverse();
        let index = ProcessIndex::new(&processes);
        for time in (0..200).chain([u64::MAX - 1, u64::MAX]) {
            let expected = reference(&processes, time);
            let actual = index.associate(None, time, 999).unwrap();
            assert_eq!(actual.pid, expected.unwrap_or(999), "time {time}");
            assert_eq!(
                actual.method,
                if expected.is_some() {
                    "nearest_process_lifetime"
                } else {
                    "root_target_fallback"
                }
            );
        }
        assert_eq!(
            index.associate(Some(999), 20, 10).unwrap().image,
            "<unknown>"
        );
        assert!(!index.associate(Some(20), u64::MAX, 10).unwrap().inferred);
        assert_eq!(
            ProcessIndex::new(&[]).associate(None, 0, 42).unwrap().pid,
            42
        );
    }

    #[test]
    fn image_expansion_budget_rejects_before_cloning_for_all_pid_routes() {
        let mut p = process(1, &[(0, "observed")]);
        p.image = "x".repeat(4096);
        let processes = vec![p];
        for explicit in [Some(1), None] {
            let mut index = ProcessIndex::new(&processes);
            index.budget.maximum = 8192;
            let shared = index.budget.clone();
            index.associate(explicit, 1, 1).unwrap();
            index.associate(explicit, 1, 1).unwrap();
            assert!(
                index
                    .associate(explicit, 1, 1)
                    .unwrap_err()
                    .to_string()
                    .contains("analysis is incomplete")
            );
            assert!(
                shared.check().is_err(),
                "structured import sees the same exhausted budget"
            );
        }
    }

    #[test]
    fn large_overlapping_lifetimes_have_a_linear_size_index_and_indexed_queries() {
        let processes = (1..=50_000)
            .map(|pid| process(pid, &[(0, "observed")]))
            .collect::<Vec<_>>();
        let index = ProcessIndex::new(&processes);
        assert!(index.before.0.len() + index.after.0.len() <= processes.len() * 4);
        for time in 1..=50_000 {
            assert_eq!(index.associate(None, time, 50_000).unwrap().pid, 1);
        }
    }
}
