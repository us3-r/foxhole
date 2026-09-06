use crate::request::RunLayout;
use crate::runner::{AgentError, AgentResult};
use foxhole::sandbox::hyperv::guest_protocol::{
    GuestError, MAX_STATUS_BYTES, PROTOCOL_VERSION, ProtocolState, ProtocolStateMachine,
    StatusRecord, read_bounded_json, unix_timestamp_ms, write_atomic_json_new,
};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

const START_POLL_INTERVAL: Duration = Duration::from_millis(100);
const START_WAIT_LIMIT: Duration = Duration::from_secs(60);
static OUTPUT_TEMPORARY_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentClaim {
    protocol_version: u32,
    run_id: String,
    agent_version: String,
    process_id: u32,
    timestamp_ms: u64,
}

#[derive(Debug)]
pub struct RunClaim;

impl RunClaim {
    pub fn acquire(layout: &RunLayout, run_id: &str, agent_version: &str) -> AgentResult<Self> {
        let claim = AgentClaim {
            protocol_version: PROTOCOL_VERSION,
            run_id: run_id.to_string(),
            agent_version: agent_version.to_string(),
            process_id: std::process::id(),
            timestamp_ms: unix_timestamp_ms(),
        };
        write_atomic_json_new(
            &layout.status.join("agent-claim.json"),
            &claim,
            MAX_STATUS_BYTES,
        )
        .map_err(|error| {
            AgentError::new(
                "claim",
                "run_already_claimed",
                format!("exclusively claim the run: {error}"),
            )
        })?;
        Ok(Self)
    }
}

pub struct StatusPublisher {
    status_directory: std::path::PathBuf,
    request_sha256: String,
    machine: ProtocolStateMachine,
}

impl StatusPublisher {
    pub fn open(layout: &RunLayout, run_id: &str, request_sha256: String) -> AgentResult<Self> {
        let mut machine = ProtocolStateMachine::new(run_id).map_err(|error| {
            AgentError::new(
                "protocol",
                "invalid_run_id",
                format!("initialize protocol state: {error}"),
            )
        })?;
        reject_existing_guest_states(layout)?;

        let mut records = Vec::new();
        for state in [
            ProtocolState::HostReady,
            ProtocolState::RequestWritten,
            ProtocolState::StartAllowed,
            ProtocolState::CancelRequested,
        ] {
            let path = layout.status.join(state.file_name());
            if path.exists() {
                records.push(read_status(&path)?);
            }
        }
        records.sort_by_key(|record| record.sequence);
        for record in records {
            validate_request_digest(&record, &request_sha256)?;
            machine.observe(&record).map_err(|error| {
                AgentError::new(
                    "protocol",
                    "invalid_host_state",
                    format!("validate host state: {error}"),
                )
            })?;
        }
        if !machine.has_seen(ProtocolState::HostReady)
            || !machine.has_seen(ProtocolState::RequestWritten)
        {
            return Err(AgentError::new(
                "protocol",
                "host_not_ready",
                "host-ready and request-written status records are required",
            ));
        }
        Ok(Self {
            status_directory: layout.status.clone(),
            request_sha256,
            machine,
        })
    }

    pub fn has_seen(&self, state: ProtocolState) -> bool {
        self.machine.has_seen(state)
    }

    pub fn publish(
        &mut self,
        state: ProtocolState,
        error: Option<GuestError>,
        result_sha256: Option<String>,
    ) -> AgentResult<()> {
        let mut record = StatusRecord::new(
            self.run_id(),
            self.machine.last_sequence().saturating_add(1),
            state,
        );
        record.request_sha256 = Some(self.request_sha256.clone());
        record.result_sha256 = result_sha256;
        record.error = error;

        let mut next = self.machine.clone();
        next.observe(&record).map_err(|error| {
            AgentError::new(
                "protocol",
                "invalid_guest_state",
                format!("validate guest state transition: {error}"),
            )
        })?;
        let destination = self.status_directory.join(state.file_name());
        write_atomic_json_new(&destination, &record, MAX_STATUS_BYTES).map_err(|error| {
            AgentError::new(
                "protocol",
                "publish_guest_state",
                format!("publish state {state:?}: {error}"),
            )
        })?;
        self.machine = next;
        Ok(())
    }

    pub fn wait_for_start_or_cancel(&mut self) -> AgentResult<StartDecision> {
        if self.machine.has_seen(ProtocolState::CancelRequested) {
            return Ok(StartDecision::Cancel);
        }
        if self.machine.has_seen(ProtocolState::StartAllowed) {
            return Ok(StartDecision::Start);
        }
        let started = Instant::now();
        loop {
            let mut new_records = Vec::new();
            for state in [ProtocolState::StartAllowed, ProtocolState::CancelRequested] {
                if self.machine.has_seen(state) {
                    continue;
                }
                let path = self.status_directory.join(state.file_name());
                if path.exists() {
                    new_records.push(read_status(&path)?);
                }
            }
            new_records.sort_by_key(|record| record.sequence);
            for record in new_records {
                validate_request_digest(&record, &self.request_sha256)?;
                self.machine.observe(&record).map_err(|error| {
                    AgentError::new(
                        "protocol",
                        "invalid_host_state",
                        format!("validate live host state: {error}"),
                    )
                })?;
            }
            if self.machine.has_seen(ProtocolState::CancelRequested) {
                return Ok(StartDecision::Cancel);
            }
            if self.machine.has_seen(ProtocolState::StartAllowed) {
                return Ok(StartDecision::Start);
            }
            if started.elapsed() >= START_WAIT_LIMIT {
                return Err(AgentError::new(
                    "protocol",
                    "start_timeout",
                    "host did not publish start-allowed within 60 seconds",
                ));
            }
            thread::sleep(START_POLL_INTERVAL);
        }
    }

    fn run_id(&self) -> &str {
        self.machine.run_id()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartDecision {
    Start,
    Cancel,
}

fn read_status(path: &Path) -> AgentResult<StatusRecord> {
    let record = read_bounded_json::<StatusRecord>(path, MAX_STATUS_BYTES).map_err(|error| {
        AgentError::new(
            "protocol",
            "invalid_status_json",
            format!("read {}: {error}", path.display()),
        )
    })?;
    record.validate().map_err(|error| {
        AgentError::new(
            "protocol",
            "invalid_status",
            format!("validate {}: {error}", path.display()),
        )
    })?;
    Ok(record)
}

fn validate_request_digest(record: &StatusRecord, expected: &str) -> AgentResult<()> {
    if let Some(actual) = record.request_sha256.as_deref()
        && !actual.eq_ignore_ascii_case(expected)
    {
        return Err(AgentError::new(
            "protocol",
            "request_digest_mismatch",
            "host status refers to different request.json bytes",
        ));
    }
    Ok(())
}

fn reject_existing_guest_states(layout: &RunLayout) -> AgentResult<()> {
    for state in [
        ProtocolState::GuestReady,
        ProtocolState::Running,
        ProtocolState::Completed,
        ProtocolState::Failed,
        ProtocolState::ShutdownReady,
    ] {
        if layout.status.join(state.file_name()).exists() {
            return Err(AgentError::new(
                "claim",
                "stale_guest_state",
                format!("run-data package already contains guest state {state:?}"),
            ));
        }
    }
    let mut output_entries = fs::read_dir(&layout.output).map_err(|error| {
        AgentError::with_source(
            "claim",
            "inspect_output",
            "inspect the run output directory",
            error,
        )
    })?;
    if output_entries
        .next()
        .transpose()
        .map_err(|error| {
            AgentError::with_source(
                "claim",
                "inspect_output",
                "enumerate the run output directory",
                error,
            )
        })?
        .is_some()
    {
        return Err(AgentError::new(
            "claim",
            "stale_output",
            "run-data package output directory is not empty",
        ));
    }
    Ok(())
}

pub fn sha256_file(path: &Path, maximum_bytes: u64) -> AgentResult<String> {
    let mut file = File::open(path).map_err(|error| {
        AgentError::with_source(
            "checksum",
            "open_file",
            format!("open {} for hashing", path.display()),
            error,
        )
    })?;
    let metadata = file.metadata().map_err(|error| {
        AgentError::with_source(
            "checksum",
            "inspect_file",
            format!("inspect {} for hashing", path.display()),
            error,
        )
    })?;
    if !metadata.is_file() || metadata.len() > maximum_bytes {
        return Err(AgentError::new(
            "checksum",
            "invalid_file",
            format!("{} is not a bounded regular file", path.display()),
        ));
    }
    let mut hasher = Sha256::new();
    let mut total = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer).map_err(|error| {
            AgentError::with_source(
                "checksum",
                "read_file",
                format!("hash {}", path.display()),
                error,
            )
        })?;
        if count == 0 {
            break;
        }
        total = total.checked_add(count as u64).ok_or_else(|| {
            AgentError::new("checksum", "size_overflow", "hashed byte count overflowed")
        })?;
        if total > maximum_bytes {
            return Err(AgentError::new(
                "checksum",
                "file_grew",
                "file grew beyond its hashing limit",
            ));
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hasher.finish_hex())
}

pub fn write_atomic_bytes_new(path: &Path, bytes: &[u8], maximum_bytes: u64) -> AgentResult<()> {
    if bytes.len() as u64 > maximum_bytes {
        return Err(AgentError::new(
            "result",
            "output_too_large",
            format!("{} exceeds its output byte limit", path.display()),
        ));
    }
    let parent = path.parent().ok_or_else(|| {
        AgentError::new(
            "result",
            "invalid_output_path",
            "output destination has no parent",
        )
    })?;
    let name = path.file_name().ok_or_else(|| {
        AgentError::new(
            "result",
            "invalid_output_path",
            "output destination has no file name",
        )
    })?;
    let counter = OUTPUT_TEMPORARY_COUNTER.fetch_add(1, Ordering::Relaxed);
    let temporary = parent.join(format!(
        ".{}.{}.{}.tmp",
        name.to_string_lossy(),
        std::process::id(),
        counter
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|error| {
            AgentError::with_source(
                "result",
                "create_temporary_output",
                format!("create {}", temporary.display()),
                error,
            )
        })?;
    let result = (|| {
        file.write_all(bytes)?;
        file.flush()?;
        file.sync_all()?;
        drop(file);
        fs::hard_link(&temporary, path)?;
        fs::remove_file(&temporary)
    })();
    if let Err(error) = result {
        let _ = fs::remove_file(&temporary);
        return Err(AgentError::with_source(
            "result",
            "publish_output",
            format!("publish {} without replacement", path.display()),
            error,
        ));
    }
    Ok(())
}

pub struct Sha256 {
    state: [u32; 8],
    block: [u8; 64],
    block_len: usize,
    total_len: u64,
}

impl Sha256 {
    pub fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            block: [0; 64],
            block_len: 0,
            total_len: 0,
        }
    }

    pub fn update(&mut self, mut input: &[u8]) {
        self.total_len = self.total_len.saturating_add(input.len() as u64);
        if self.block_len != 0 {
            let count = (64 - self.block_len).min(input.len());
            self.block[self.block_len..self.block_len + count].copy_from_slice(&input[..count]);
            self.block_len += count;
            input = &input[count..];
            if self.block_len == 64 {
                let block = self.block;
                self.transform(&block);
                self.block_len = 0;
            }
        }
        while input.len() >= 64 {
            let mut block = [0u8; 64];
            block.copy_from_slice(&input[..64]);
            self.transform(&block);
            input = &input[64..];
        }
        if !input.is_empty() {
            self.block[..input.len()].copy_from_slice(input);
            self.block_len = input.len();
        }
    }

    pub fn finish_hex(mut self) -> String {
        let bit_len = self.total_len.saturating_mul(8);
        self.block[self.block_len] = 0x80;
        self.block_len += 1;
        if self.block_len > 56 {
            self.block[self.block_len..].fill(0);
            let block = self.block;
            self.transform(&block);
            self.block = [0; 64];
            self.block_len = 0;
        }
        self.block[self.block_len..56].fill(0);
        self.block[56..64].copy_from_slice(&bit_len.to_be_bytes());
        let block = self.block;
        self.transform(&block);
        let mut output = String::with_capacity(64);
        for word in self.state {
            use std::fmt::Write as _;
            let _ = write!(&mut output, "{word:08x}");
        }
        output
    }

    fn transform(&mut self, block: &[u8; 64]) {
        const K: [u32; 64] = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
            0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
            0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
            0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
            0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
            0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
            0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
            0xc67178f2,
        ];
        let mut words = [0u32; 64];
        for (index, chunk) in block.chunks_exact(4).enumerate() {
            words[index] = u32::from_be_bytes(chunk.try_into().expect("four-byte SHA word"));
        }
        for index in 16..64 {
            let s0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let s1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(s0)
                .wrapping_add(words[index - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;
        for index in 0..64 {
            let choice = (e & f) ^ ((!e) & g);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let sum0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let sum1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let temporary1 = h
                .wrapping_add(sum1)
                .wrapping_add(choice)
                .wrapping_add(K[index])
                .wrapping_add(words[index]);
            let temporary2 = sum0.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temporary1);
            d = c;
            c = b;
            b = a;
            a = temporary1.wrapping_add(temporary2);
        }
        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_matches_standard_vectors_and_chunking() {
        let mut empty = Sha256::new();
        empty.update(b"");
        assert_eq!(
            empty.finish_hex(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let mut abc = Sha256::new();
        for byte in b"abc" {
            abc.update(std::slice::from_ref(byte));
        }
        assert_eq!(
            abc.finish_hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn exclusive_claim_prevents_replay() {
        let root =
            std::env::temp_dir().join(format!("foxhole-agent-claim-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        for directory in ["input", "output", "status"] {
            fs::create_dir_all(root.join(directory)).unwrap();
        }
        let layout = RunLayout {
            root: root.clone(),
            request: root.join("request.json"),
            input: root.join("input"),
            output: root.join("output"),
            status: root.join("status"),
        };
        RunClaim::acquire(&layout, "0123456789abcdef", "test-agent").unwrap();
        let replay = RunClaim::acquire(&layout, "0123456789abcdef", "test-agent")
            .expect_err("a claimed run must never execute again");
        assert_eq!(replay.code, "run_already_claimed");
        fs::remove_dir_all(root).unwrap();
    }
}
