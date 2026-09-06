use crate::artifact;
use crate::host_file::{self, PinnedInputFile};
use crate::sandbox::backend::{
    BackendKind, BackendMetadata, BackendState, MitigationProfile, NetworkPolicy, ReportStage,
    SandboxBackend, SandboxError, SandboxRequest, SandboxResult, StageTimer,
};
use crate::sandbox::hyperv::base_image::{self, BaseImageConfig, ValidatedBaseImage};
use crate::sandbox::hyperv::capability::{self, CapabilityReport};
use crate::sandbox::hyperv::cleanup::{self, CleanupJournal, CleanupOutcome, CleanupPhase};
use crate::sandbox::hyperv::data_disk::{
    self, DataDiskState, MAX_STAGED_TARGET_BYTES, RunDataDisk, RunDataDiskSpec,
};
use crate::sandbox::hyperv::disk::{self, DifferencingDiskSpec};
use crate::sandbox::hyperv::guest_protocol::{
    CaptureOptions, GuestExecutionProfile, GuestMitigationProfile, GuestNetworkPolicy,
    GuestResourceLimits, GuestResultEnvelope, GuestRunRequest, GuestTerminalOutcome,
    ObservationCoverage, PROTOCOL_VERSION,
};
use crate::sandbox::hyperv::network::{self, ControlledGatewayConfig, HyperVNetworkPlan};
use crate::sandbox::hyperv::powershell::{NativePowerShell, PowerShellExecutor};
use crate::sandbox::hyperv::result_collector::{self, CollectionLimits};
use crate::sandbox::hyperv::vm::{self, DiskRole, VmHandle, VmSpec};
use crate::structs::{CleanupStatus, SandboxRunResult, StreamCaptureSummary};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};

pub const MAX_VM_WRITABLE_DISK_BYTES: u64 = 5 * 1024 * 1024 * 1024;
const DEFAULT_DATA_DISK_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const DEFAULT_OS_DISK_GROWTH_BYTES: u64 = MAX_VM_WRITABLE_DISK_BYTES - DEFAULT_DATA_DISK_BYTES;
const DISK_QUOTA_WATCH_INTERVAL: Duration = Duration::from_millis(50);

#[derive(Clone, Debug)]
pub struct HyperVConfig {
    pub base_image_path: PathBuf,
    pub base_manifest_path: PathBuf,
    pub run_root: PathBuf,
    pub processor_count: u16,
    pub startup_memory_bytes: u64,
    pub data_disk_bytes: u64,
    pub maximum_os_disk_growth_bytes: u64,
    pub boot_timeout_secs: u64,
    pub shutdown_grace_secs: u64,
    pub controlled_gateway: Option<ControlledGatewayConfig>,
    pub collection_limits: CollectionLimits,
}

impl HyperVConfig {
    pub fn new(
        base_image_path: impl Into<PathBuf>,
        base_manifest_path: impl Into<PathBuf>,
    ) -> SandboxResult<Self> {
        let run_root = artifact::artifact_root()
            .map_err(|error| {
                SandboxError::with_source(
                    "hyperv_configuration",
                    "resolve protected Foxhole storage",
                    error,
                )
            })?
            .join("hyperv")
            .join("runs");
        Ok(Self {
            base_image_path: base_image_path.into(),
            base_manifest_path: base_manifest_path.into(),
            run_root,
            processor_count: 2,
            startup_memory_bytes: 2 * 1024 * 1024 * 1024,
            data_disk_bytes: DEFAULT_DATA_DISK_BYTES,
            maximum_os_disk_growth_bytes: DEFAULT_OS_DISK_GROWTH_BYTES,
            boot_timeout_secs: 120,
            shutdown_grace_secs: 15,
            controlled_gateway: None,
            collection_limits: CollectionLimits::default(),
        })
    }

    fn validate(&self) -> SandboxResult<()> {
        if !self.run_root.is_absolute()
            || self.processor_count == 0
            || self.processor_count > vm::MAX_PROCESSOR_COUNT
            || !(vm::MIN_STARTUP_MEMORY_BYTES..=vm::MAX_STARTUP_MEMORY_BYTES)
                .contains(&self.startup_memory_bytes)
            || !(data_disk::MIN_DATA_DISK_BYTES..=data_disk::MAX_DATA_DISK_BYTES)
                .contains(&self.data_disk_bytes)
            || !(512 * 1024 * 1024..=128 * 1024 * 1024 * 1024)
                .contains(&self.maximum_os_disk_growth_bytes)
            || self
                .data_disk_bytes
                .checked_add(self.maximum_os_disk_growth_bytes)
                .is_none_or(|total| total > MAX_VM_WRITABLE_DISK_BYTES)
            || self.boot_timeout_secs == 0
            || self.shutdown_grace_secs == 0
        {
            return Err(SandboxError::new(
                "hyperv_configuration",
                "Hyper-V run root, CPU, memory, disk, or timeout configuration is invalid",
            ));
        }
        Ok(())
    }
}

pub struct HyperVSandboxRun {
    pub result: SandboxRunResult,
    pub target_path: PathBuf,
    pub target_size_bytes: u64,
    pub target_sha256: String,
    pub run_id: String,
    pub guest_image_version: String,
    pub cleanup: CleanupOutcome,
    pub metadata: BackendMetadata,
    pub stages: Vec<ReportStage>,
}

enum PreparedRun {
    DryRun(Box<DryPrepared>),
    Preparing(Box<CleanupJournal>),
    Live(Box<LivePrepared>),
}

struct DryPrepared {
    request: SandboxRequest,
    _target: PinnedInputFile,
    _base: ValidatedBaseImage,
}

struct LivePrepared {
    request: SandboxRequest,
    run_id: String,
    _base: ValidatedBaseImage,
    data_disk: RunDataDisk,
    vm: VmHandle,
    network_plan: HyperVNetworkPlan,
    request_sha256: String,
    journal: CleanupJournal,
    _run_directory_pins: Vec<File>,
}

pub struct HyperVBackend {
    state: BackendState,
    config: HyperVConfig,
    executor: Arc<dyn PowerShellExecutor>,
    prepared: Option<PreparedRun>,
    started_at: Option<Instant>,
    target_path: Option<PathBuf>,
    target_size_bytes: u64,
    target_sha256: Option<String>,
    run_id: Option<String>,
    guest_image_version: Option<String>,
    cleanup_outcome: CleanupOutcome,
    execution_stages: Vec<ReportStage>,
    network_plan: Option<HyperVNetworkPlan>,
    network_pre_verification: Option<network::NetworkAttachment>,
    network_post_verification: Option<network::NetworkAttachment>,
}

impl HyperVBackend {
    pub fn new(config: HyperVConfig) -> Self {
        Self::with_executor(config, Arc::new(NativePowerShell))
    }

    pub(crate) fn with_executor(
        config: HyperVConfig,
        executor: Arc<dyn PowerShellExecutor>,
    ) -> Self {
        Self {
            state: BackendState::Created,
            config,
            executor,
            prepared: None,
            started_at: None,
            target_path: None,
            target_size_bytes: 0,
            target_sha256: None,
            run_id: None,
            guest_image_version: None,
            cleanup_outcome: CleanupOutcome::default(),
            execution_stages: Vec::new(),
            network_plan: None,
            network_pre_verification: None,
            network_post_verification: None,
        }
    }

    pub fn state(&self) -> BackendState {
        self.state
    }

    pub fn capability(&self) -> SandboxResult<CapabilityReport> {
        capability::detect(self.executor.as_ref())
    }

    pub fn cleanup_outcome(&self) -> &CleanupOutcome {
        &self.cleanup_outcome
    }
}

pub fn start_with_request(
    request: SandboxRequest,
    config: HyperVConfig,
) -> SandboxResult<HyperVSandboxRun> {
    println!("[cli debug] in start_with_request @backend");
    let _elapsed_debug_timer = ElapsedDebugTimer::start();
    let mut backend = HyperVBackend::new(config);
    let validation_timer = StageTimer::start("request_validation");
    request.validate_for_backend(BackendKind::HyperV)?;
    let validation_stage = validation_timer.finish(true, Vec::new(), Vec::new());

    println!("[cli debug] pass timer@request_validation");

    let preparation_timer = StageTimer::start("preparation");
    if let Err(preparation_error) = backend.prepare(&request) {
        crate::interrupt::begin_cleanup();
        let cleanup_error = backend.cleanup().err();
        return match cleanup_error {
            Some(cleanup_error) => Err(SandboxError::new(
                "hyperv_preparation_and_cleanup",
                format!("{preparation_error}; cleanup also failed: {cleanup_error}"),
            )),
            None => Err(preparation_error),
        };
    }

    println!("[cli debug] pass timer@preparation");

    let preparation_stage = preparation_timer.finish(true, Vec::new(), Vec::new());

    let execution_timer = StageTimer::start("execution");
    let mut execution = backend.execute(&request);
    let execution_stage = execution_timer.finish(
        execution.is_ok(),
        Vec::new(),
        execution
            .as_ref()
            .err()
            .map(ToString::to_string)
            .into_iter()
            .collect(),
    );

    println!("[cli debug] pass timer@execution");

    crate::interrupt::begin_cleanup();
    let cleanup_timer = StageTimer::start("cleanup");
    let cleanup_result = backend.cleanup();
    let cleanup_stage = cleanup_timer.finish(
        cleanup_result.is_ok(),
        backend.cleanup_outcome.warnings.clone(),
        cleanup_result
            .as_ref()
            .err()
            .map(ToString::to_string)
            .into_iter()
            .collect(),
    );

    println!("[cli debug] pass timer@cleanup");

    match (&mut execution, cleanup_result) {
        (Ok(result), Ok(())) => {
            result.cleanup.attempted = backend.cleanup_outcome.attempted;
            result.cleanup.success = backend.cleanup_outcome.success;
            result.cleanup.warnings = backend.cleanup_outcome.warnings.clone();
            result.cleanup.leftover_resources = backend.cleanup_outcome.leftover_resources.clone();
        }
        (Ok(result), Err(cleanup_error)) => {
            result.cleanup.attempted = true;
            result.cleanup.success = false;
            result.cleanup.warnings.push(cleanup_error.to_string());
            result.cleanup.leftover_resources = backend.cleanup_outcome.leftover_resources.clone();
        }
        (Err(execution_error), Err(cleanup_error)) => {
            return Err(SandboxError::new(
                "hyperv_execution_and_cleanup",
                format!("{execution_error}; cleanup also failed: {cleanup_error}"),
            ));
        }
        (Err(_), Ok(())) => {}
    }
    let result = execution?;
    let run_id = backend
        .run_id
        .clone()
        .ok_or_else(|| SandboxError::new("hyperv_result", "run identifier was not retained"))?;
    let guest_image_version = backend.guest_image_version.clone().ok_or_else(|| {
        SandboxError::new("hyperv_result", "guest image version was not retained")
    })?;
    let network_metadata = network::metadata(
        backend
            .network_plan
            .as_ref()
            .ok_or_else(|| SandboxError::new("hyperv_result", "network plan was not retained"))?,
        backend.network_pre_verification.clone(),
        backend.network_post_verification.clone(),
        backend.cleanup_outcome.removed_resources.clone(),
        backend.cleanup_outcome.warnings.clone(),
    );
    let metadata = BackendMetadata::HyperV {
        run_id: run_id.clone(),
        guest_image_version: guest_image_version.clone(),
        protocol_version: PROTOCOL_VERSION,
        vm_generation: 2,
        secure_boot: true,
        cpu_count: backend.config.processor_count,
        startup_memory_bytes: backend.config.startup_memory_bytes,
        data_disk_bytes: backend.config.data_disk_bytes,
        maximum_os_disk_growth_bytes: backend.config.maximum_os_disk_growth_bytes,
        network_mode: request.network_policy.name().to_string(),
        network: network_metadata,
    };
    let mut stages = vec![validation_stage, preparation_stage, execution_stage];
    stages.append(&mut backend.execution_stages);
    stages.push(cleanup_stage);
    Ok(HyperVSandboxRun {
        result,
        target_path: backend.target_path.ok_or_else(|| {
            SandboxError::new("hyperv_result", "target metadata was not retained")
        })?,
        target_size_bytes: backend.target_size_bytes,
        target_sha256: backend.target_sha256.ok_or_else(|| {
            SandboxError::new("hyperv_result", "target integrity hash was not retained")
        })?,
        run_id,
        guest_image_version,
        cleanup: backend.cleanup_outcome,
        metadata,
        stages,
    })
}

struct ElapsedDebugTimer {
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}

impl ElapsedDebugTimer {
    fn start() -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let started_at = Instant::now();
        let worker = thread::spawn(move || {
            let mut last_report = started_at;
            while !worker_stop.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_secs(1));
                if !worker_stop.load(Ordering::Relaxed)
                    && last_report.elapsed() >= Duration::from_secs(10)
                {
                    print!(
                        "\r[cli debug] total elapsed: {}s",
                        started_at.elapsed().as_secs()
                    );
                    let _ = io::stdout().flush();
                    last_report = Instant::now();
                }
            }
        });
        Self {
            stop,
            worker: Some(worker),
        }
    }
}

impl Drop for ElapsedDebugTimer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        println!();
    }
}

impl SandboxBackend for HyperVBackend {
    fn prepare(&mut self, request: &SandboxRequest) -> SandboxResult<()> {
        println!("[cli debug] in prepare");
        if self.state != BackendState::Created {
            return Err(SandboxError::new(
                "hyperv_prepare",
                format!("Hyper-V backend cannot prepare from {:?}", self.state),
            ));
        }
        self.state = BackendState::Preparing;
        self.started_at = Some(Instant::now());
        let result = self.prepare_inner(request);
        self.state = if result.is_ok() {
            BackendState::Ready
        } else {
            BackendState::Failed
        };
        result
    }

    fn execute(&mut self, request: &SandboxRequest) -> SandboxResult<SandboxRunResult> {
        if self.state != BackendState::Ready {
            return Err(SandboxError::new(
                "hyperv_execute",
                format!("Hyper-V backend cannot execute from {:?}", self.state),
            ));
        }
        self.state = BackendState::Running;
        let started = self.started_at.unwrap_or_else(Instant::now);
        let result = self.execute_inner(request, started);
        self.state = if result.is_ok() {
            BackendState::Completed
        } else {
            BackendState::Failed
        };
        result
    }

    fn cleanup(&mut self) -> SandboxResult<()> {
        if self.state == BackendState::Finished {
            return Ok(());
        }
        self.state = BackendState::Cleaning;
        self.cleanup_outcome = match self.prepared.as_mut() {
            Some(PreparedRun::Live(prepared)) => cleanup::cleanup_resources(
                self.executor.as_ref(),
                &mut prepared.journal,
                Duration::from_secs(self.config.shutdown_grace_secs),
            ),
            Some(PreparedRun::Preparing(journal)) => cleanup::cleanup_resources(
                self.executor.as_ref(),
                journal,
                Duration::from_secs(self.config.shutdown_grace_secs),
            ),
            Some(PreparedRun::DryRun(_)) | None => CleanupOutcome {
                attempted: true,
                success: true,
                warnings: Vec::new(),
                leftover_resources: Vec::new(),
                removed_resources: Vec::new(),
            },
        };
        self.prepared = None;
        self.state = BackendState::Finished;
        if self.cleanup_outcome.success {
            Ok(())
        } else {
            Err(SandboxError::new(
                "hyperv_cleanup",
                if self.cleanup_outcome.warnings.is_empty() {
                    "Hyper-V cleanup left resources behind".to_string()
                } else {
                    self.cleanup_outcome.warnings.join("; ")
                },
            ))
        }
    }
}

impl HyperVBackend {
    fn prepare_inner(&mut self, request: &SandboxRequest) -> SandboxResult<()> {
        println!("[cli debug] hyperv prepare: validating configuration and request");
        self.config.validate()?;
        request.validate_for_backend(BackendKind::HyperV)?;
        if !request.mapped_paths.is_empty() {
            return Err(SandboxError::new(
                "hyperv_prepare",
                "Hyper-V mapped paths are not supported; copy approved inputs into the run package",
            ));
        }
        println!("[cli debug] hyperv prepare: probing host capability");
        let capability = self.capability()?;
        capability.require_available()?;

        println!("[cli debug] hyperv prepare: pinning target and calculating hash");
        let mut target = host_file::open_pinned_input(&request.target, MAX_STAGED_TARGET_BYTES)
            .map_err(|error| {
                SandboxError::with_source("hyperv_prepare", "pin target for VM staging", error)
            })?;
        let canonical_target =
            pinned_input_path(&target.file, &request.target).map_err(|error| {
                SandboxError::with_source("hyperv_prepare", "resolve pinned target path", error)
            })?;
        let target_sha256 = hash_pinned_target(&mut target.file, target.len)?;
        self.target_path = Some(canonical_target.clone());
        self.target_size_bytes = target.len;
        self.target_sha256 = Some(target_sha256.clone());

        let base_config = BaseImageConfig::new(
            self.config.base_image_path.clone(),
            self.config.base_manifest_path.clone(),
        );
        println!("[cli debug] hyperv prepare: validating base image");
        let base = base_image::validate(self.executor.as_ref(), &base_config)?;
        self.guest_image_version = Some(base.manifest.image_version.clone());
        let mut network_plan = network::plan(
            &request.network_policy,
            self.config.controlled_gateway.as_ref(),
        )?;
        if matches!(network_plan, network::HyperVNetworkPlan::Controlled { .. }) {
            capability.require_controlled_network_available()?;
        }
        self.network_plan = Some(network_plan.clone());
        let run_id = artifact::random_hex(16).map_err(|error| {
            SandboxError::with_source("hyperv_prepare", "generate run identifier", error)
        })?;
        self.run_id = Some(run_id.clone());
        let required_data_bytes = target
            .len
            .checked_add(self.config.collection_limits.maximum_total_bytes)
            .and_then(|value| value.checked_add(128 * 1024 * 1024))
            .ok_or_else(|| {
                SandboxError::new(
                    "hyperv_configuration",
                    "run-data capacity calculation overflowed",
                )
            })?;
        if self.config.data_disk_bytes < required_data_bytes {
            return Err(SandboxError::new(
                "hyperv_configuration",
                format!(
                    "run-data disk is too small for the target and configured output budget (need at least {required_data_bytes} bytes)"
                ),
            ));
        }

        if request.dry_run {
            self.prepared = Some(PreparedRun::DryRun(Box::new(DryPrepared {
                request: request.clone(),
                _target: target,
                _base: base,
            })));
            return Ok(());
        }

        artifact::validate_absolute_local_path(&self.config.run_root).map_err(|error| {
            SandboxError::with_source(
                "hyperv_prepare",
                "Hyper-V run root must be an absolute local path",
                error,
            )
        })?;
        artifact::verify_local_fixed_volume(&self.config.run_root).map_err(|error| {
            SandboxError::with_source(
                "hyperv_prepare",
                "Hyper-V run root must be on a fixed local volume",
                error,
            )
        })?;
        let _root_pins =
            artifact::pin_safe_directory_tree(&self.config.run_root, true).map_err(|error| {
                SandboxError::with_source("hyperv_prepare", "create protected run root", error)
            })?;
        artifact::harden_owned_directory_chain(&self.config.run_root, &self.config.run_root)
            .map_err(|error| {
                SandboxError::with_source("hyperv_prepare", "harden Hyper-V run root", error)
            })?;
        let run_root = self.config.run_root.join(&run_id);
        std::fs::create_dir(&run_root).map_err(|error| {
            SandboxError::with_source(
                "hyperv_prepare",
                "create exclusive per-run directory",
                error,
            )
        })?;
        artifact::harden_owned_directory_chain(&self.config.run_root, &run_root).map_err(
            |error| SandboxError::with_source("hyperv_prepare", "harden per-run directory", error),
        )?;
        let run_directory_pins =
            artifact::pin_safe_directory_tree(&run_root, false).map_err(|error| {
                SandboxError::with_source("hyperv_prepare", "pin per-run directory", error)
            })?;
        let mut journal = CleanupJournal::new(run_id.clone(), run_root.clone())?;
        journal.persist()?;
        let _ = cleanup::latest_journal(&run_root)?;
        self.track_preparation(&journal);
        if let Some(lease) = network::activate(&mut network_plan, &run_id, &run_root)? {
            journal.network = Some(network::NetworkOwnedResources {
                guest_lease: Some(lease),
                ..network::NetworkOwnedResources::default()
            });
            journal.persist()?;
            self.track_preparation(&journal);
        }
        self.network_plan = Some(network_plan.clone());
        println!("[cli debug] hyperv prepare: building guest request");
        let guest_request =
            build_guest_request(request, &network_plan, &run_id, Some(target_sha256))?;
        let required_free_bytes = self
            .config
            .maximum_os_disk_growth_bytes
            .checked_add(self.config.data_disk_bytes)
            .and_then(|value| value.checked_add(2 * 1024 * 1024 * 1024))
            .ok_or_else(|| {
                SandboxError::new(
                    "hyperv_configuration",
                    "host free-space reservation calculation overflowed",
                )
            })?;
        require_host_free_space(&run_root, required_free_bytes)?;

        println!("[cli debug] hyperv prepare: creating differencing OS disk");
        let os_disk_path = run_root.join("os-diff.vhdx");
        journal.os_disk = Some(os_disk_path.clone());
        journal.persist()?;
        self.track_preparation(&journal);
        let os_disk_spec = DifferencingDiskSpec {
            run_root: run_root.clone(),
            path: os_disk_path.clone(),
            parent_path: base.path.clone(),
        };
        let os_disk = disk::create_differencing_disk(self.executor.as_ref(), &os_disk_spec)?;
        journal.os_disk_identifier = os_disk.disk_identifier.clone();
        journal.persist()?;
        self.track_preparation(&journal);

        let mount_path = run_root.join("data-mount");
        std::fs::create_dir(&mount_path).map_err(|error| {
            SandboxError::with_source("hyperv_prepare", "create data-disk mount directory", error)
        })?;
        let data_spec = RunDataDiskSpec {
            run_id: run_id.clone(),
            run_root: run_root.clone(),
            path: run_root.join("run-data.vhdx"),
            mount_path,
            size_bytes: self.config.data_disk_bytes,
        };
        journal.data_disk = Some(RunDataDisk {
            path: data_spec.path.clone(),
            mount_path: data_spec.mount_path.clone(),
            size_bytes: data_spec.size_bytes,
            label: data_spec.label()?,
            disk_unique_id: None,
            vhd_identifier: None,
            state: DataDiskState::Planned,
        });
        journal.persist()?;
        self.track_preparation(&journal);
        println!("[cli debug] hyperv prepare: creating and mounting run-data disk");
        let mut data_disk = data_disk::create_and_mount(self.executor.as_ref(), &data_spec)?;
        println!("[cli debug] hyperv prepare: staging guest package on run-data disk");
        journal.data_disk = Some(data_disk.clone());
        journal.persist()?;
        self.track_preparation(&journal);

        let mut target_file = target.file;
        let request_sha256 =
            data_disk::stage_package(&data_disk.mount_path, &guest_request, &mut target_file)?;
        println!("[cli debug] hyperv prepare: dismounting run-data disk");
        data_disk::dismount(self.executor.as_ref(), &mut data_disk)?;
        println!("[cli debug] hyperv prepare: creating disposable VM");
        journal.data_disk = Some(data_disk.clone());
        journal.persist()?;
        self.track_preparation(&journal);

        let vm_spec = VmSpec::new(
            run_id.clone(),
            run_root.clone(),
            self.config.processor_count,
            self.config.startup_memory_bytes,
        );
        let vm = vm::create(self.executor.as_ref(), &vm_spec)?;
        journal.vm = Some(vm.clone());
        journal.phase = CleanupPhase::VmCreated;
        journal.persist()?;
        self.track_preparation(&journal);
        vm::attach_disk(
            self.executor.as_ref(),
            &vm,
            &os_disk_path,
            DiskRole::OperatingSystem,
        )?;
        println!("[cli debug] hyperv prepare: attaching run-data disk");
        vm::attach_disk(
            self.executor.as_ref(),
            &vm,
            &data_disk.path,
            DiskRole::RunData,
        )?;
        if matches!(network_plan, HyperVNetworkPlan::Controlled { .. }) {
            network::prepare_controlled_adapter(self.executor.as_ref(), &vm.id, &mut network_plan)?;
            // Persist exact firewall, capture, and lease ownership before those host resources are
            // created, so interruption at any later instruction remains recoverable.
            journal.network = Some(network::owned_resources(&vm.id, &run_id, &network_plan)?);
            journal.persist()?;
            self.track_preparation(&journal);
            // The exact creator/adapter scope exists only after the VM NIC is attached. Keep the
            // report-side plan synchronized with the attested identity learned above.
            self.network_plan = Some(network_plan.clone());
        }
        println!("[cli debug] hyperv prepare: configuring VM network");
        network::configure(self.executor.as_ref(), &vm.id, &network_plan)?;
        println!("[cli debug] hyperv prepare: verifying VM network");
        let pre_verification = network::verify(self.executor.as_ref(), &vm.id, &network_plan)?;
        self.network_pre_verification = Some(pre_verification);
        println!("[cli debug] hyperv prepare: complete");
        journal.persist()?;
        self.track_preparation(&journal);

        self.prepared = Some(PreparedRun::Live(Box::new(LivePrepared {
            request: request.clone(),
            run_id,
            _base: base,
            data_disk,
            vm,
            network_plan,
            request_sha256,
            journal,
            _run_directory_pins: run_directory_pins,
        })));
        Ok(())
    }

    fn execute_inner(
        &mut self,
        request: &SandboxRequest,
        started: Instant,
    ) -> SandboxResult<SandboxRunResult> {
        let (prepared_slot, execution_stages) = (&mut self.prepared, &mut self.execution_stages);
        execution_stages.clear();
        let prepared = prepared_slot.as_mut().ok_or_else(|| {
            SandboxError::new("hyperv_execute", "Hyper-V backend has no prepared run")
        })?;
        match prepared {
            PreparedRun::DryRun(prepared) => {
                if &prepared.request != request {
                    return Err(SandboxError::new(
                        "hyperv_execute",
                        "execute request differs from prepared request",
                    ));
                }
                Ok(synthetic_result(
                    request,
                    SyntheticOutcome::DryRun,
                    started.elapsed(),
                ))
            }
            PreparedRun::Preparing(_) => Err(SandboxError::new(
                "hyperv_execute",
                "Hyper-V preparation did not reach a ready state",
            )),
            PreparedRun::Live(prepared) => {
                if &prepared.request != request {
                    return Err(SandboxError::new(
                        "hyperv_execute",
                        "execute request differs from prepared request",
                    ));
                }
                println!("[cli debug] hyperv execute: verifying VM network");
                network::verify(
                    self.executor.as_ref(),
                    &prepared.vm.id,
                    &prepared.network_plan,
                )?;
                println!("[cli debug] hyperv execute: starting VM");
                vm::start(self.executor.as_ref(), &prepared.vm)?;
                prepared.journal.phase = CleanupPhase::Running;
                prepared.journal.persist()?;
                let observation_timer = StageTimer::start("observation");
                let completion_timer = StageTimer::start("timeout_or_completion");
                println!("[cli debug] hyperv execute: waiting for guest completion");
                let disk_quota = WritableDiskQuota {
                    os_disk_path: prepared.journal.os_disk.as_deref().ok_or_else(|| {
                        SandboxError::new(
                            "hyperv_runtime",
                            "differencing disk path was not retained",
                        )
                    })?,
                    data_disk_path: &prepared.data_disk.path,
                    maximum_os_disk_bytes: self.config.maximum_os_disk_growth_bytes,
                    maximum_total_disk_bytes: MAX_VM_WRITABLE_DISK_BYTES,
                };
                let completion = match wait_for_vm_completion(
                    self.executor.as_ref(),
                    &prepared.vm,
                    Duration::from_secs(
                        request
                            .timeout_secs
                            .saturating_add(self.config.boot_timeout_secs)
                            .saturating_add(self.config.shutdown_grace_secs),
                    ),
                    &disk_quota,
                    self.config.startup_memory_bytes,
                ) {
                    Ok(completion) => completion,
                    Err(runtime_error) => {
                        let _ = vm::stop(self.executor.as_ref(), &prepared.vm, true);
                        return match network::verify_after_execution(
                            self.executor.as_ref(),
                            &prepared.vm.id,
                            &prepared.network_plan,
                        ) {
                            Ok(verification) => {
                                self.network_post_verification = Some(verification);
                                Err(runtime_error)
                            }
                            Err(drift) => Err(SandboxError::new(
                                "hyperv_containment_drift",
                                format!(
                                    "{runtime_error}; post-run network containment also failed: {drift}"
                                ),
                            )),
                        };
                    }
                };
                let host_observation = match completion {
                    VmCompletion::TimedOut(observations) => {
                        let observation = observations.summary();
                        let observation_stage = observation_timer.finish(
                            true,
                            vec![
                                "host VM observation ended when the authoritative VM deadline expired"
                                    .to_string(),
                                observation.clone(),
                            ],
                            Vec::new(),
                        );
                        let completion_stage = completion_timer.finish(
                            true,
                            vec![
                                "the authoritative host VM deadline expired before authenticated guest completion"
                                    .to_string(),
                            ],
                            Vec::new(),
                        );
                        let artifact_timer = StageTimer::start("artifact_collection");
                        let stop_error = vm::stop(self.executor.as_ref(), &prepared.vm, true)
                            .err()
                            .map(|error| error.to_string());
                        let preservation = preserve_partial_guest_output(
                            self.executor.as_ref(),
                            prepared,
                            &self.config.collection_limits,
                            Duration::from_secs(self.config.shutdown_grace_secs),
                        );
                        let mut artifact_warnings = Vec::new();
                        let mut artifact_errors = Vec::new();
                        if preservation.success {
                            artifact_warnings.push(preservation.message.clone());
                        } else {
                            artifact_errors.push(preservation.message.clone());
                        }
                        if let Some(error) = stop_error {
                            artifact_errors.push(format!("force-stop request failed: {error}"));
                        }
                        let post_verification = network::verify_after_execution(
                            self.executor.as_ref(),
                            &prepared.vm.id,
                            &prepared.network_plan,
                        );
                        let drift_error = match post_verification {
                            Ok(verification) => {
                                self.network_post_verification = Some(verification);
                                None
                            }
                            Err(error) => {
                                artifact_errors
                                    .push(format!("post-run network containment drifted: {error}"));
                                Some(error)
                            }
                        };
                        let artifact_stage = artifact_timer.finish(
                            artifact_errors.is_empty(),
                            artifact_warnings,
                            artifact_errors,
                        );
                        execution_stages.extend([
                            observation_stage,
                            completion_stage,
                            artifact_stage,
                        ]);
                        if let Some(error) = drift_error {
                            return Err(SandboxError::new(
                                "hyperv_containment_drift",
                                error.to_string(),
                            ));
                        }
                        let mut result = synthetic_result(
                            request,
                            SyntheticOutcome::HostVmTimeout,
                            started.elapsed(),
                        );
                        result.monitor_warnings.push(observation);
                        result.monitor_warnings.push(preservation.message);
                        return Ok(result);
                    }
                    VmCompletion::DiskQuotaExceeded {
                        observed_bytes,
                        maximum_bytes,
                        observations,
                    } => {
                        let observation = observations.summary();
                        let quota_message = format!(
                            "disposable VM writable storage reached {observed_bytes} bytes and exceeded its {maximum_bytes} byte host quota"
                        );
                        let observation_stage = observation_timer.finish(
                            false,
                            vec![observation],
                            vec![format!("critical containment event: {quota_message}")],
                        );
                        let completion_stage = completion_timer.finish(
                            false,
                            Vec::new(),
                            vec!["VM execution was terminated by the host disk quota".to_string()],
                        );
                        let artifact_timer = StageTimer::start("artifact_collection");
                        let stop_error = vm::stop(self.executor.as_ref(), &prepared.vm, true)
                            .err()
                            .map(|error| error.to_string());
                        let preservation = preserve_partial_guest_output(
                            self.executor.as_ref(),
                            prepared,
                            &self.config.collection_limits,
                            Duration::from_secs(self.config.shutdown_grace_secs),
                        );
                        let mut artifact_warnings = Vec::new();
                        let mut artifact_errors = Vec::new();
                        if preservation.success {
                            artifact_warnings.push(preservation.message.clone());
                        } else {
                            artifact_errors.push(preservation.message.clone());
                        }
                        if let Some(error) = stop_error {
                            artifact_errors.push(format!("force-stop request failed: {error}"));
                        }
                        let post_verification = network::verify_after_execution(
                            self.executor.as_ref(),
                            &prepared.vm.id,
                            &prepared.network_plan,
                        );
                        let drift_error = match post_verification {
                            Ok(verification) => {
                                self.network_post_verification = Some(verification);
                                None
                            }
                            Err(error) => {
                                artifact_errors
                                    .push(format!("post-run network containment drifted: {error}"));
                                Some(error)
                            }
                        };
                        let artifact_stage = artifact_timer.finish(
                            artifact_errors.is_empty(),
                            artifact_warnings,
                            artifact_errors,
                        );
                        execution_stages.extend([
                            observation_stage,
                            completion_stage,
                            artifact_stage,
                        ]);
                        if let Some(error) = drift_error {
                            return Err(SandboxError::new(
                                "hyperv_containment_drift",
                                error.to_string(),
                            ));
                        }
                        return Err(os_disk_quota_error(
                            observed_bytes,
                            maximum_bytes,
                            &preservation.message,
                        ));
                    }
                    VmCompletion::PoweredOff(observations) => {
                        let observation = observations.summary();
                        prepared.journal.warnings.push(observation.clone());
                        execution_stages.push(observation_timer.finish(
                            true,
                            vec![observation.clone()],
                            Vec::new(),
                        ));
                        execution_stages.push(completion_timer.finish(
                            true,
                            Vec::new(),
                            Vec::new(),
                        ));
                        observation
                    }
                };

                println!("[cli debug] hyperv execute: verifying post-run network containment");
                let post_verification = network::verify_after_execution(
                    self.executor.as_ref(),
                    &prepared.vm.id,
                    &prepared.network_plan,
                )?;
                self.network_post_verification = Some(post_verification);

                let artifact_timer = StageTimer::start("artifact_collection");
                vm::detach_disk(
                    self.executor.as_ref(),
                    &prepared.vm,
                    &prepared.data_disk.path,
                )?;
                data_disk::mount_existing(self.executor.as_ref(), &mut prepared.data_disk)?;
                prepared.journal.data_disk = Some(prepared.data_disk.clone());
                prepared.journal.persist()?;
                let archive_root = prepared.journal.run_root.join("collected-artifacts");
                let collected = result_collector::collect(
                    &prepared
                        .data_disk
                        .mount_path
                        .join(data_disk::RUN_DIRECTORY_NAME),
                    &archive_root,
                    &prepared.run_id,
                    &prepared.request_sha256,
                    &self.config.collection_limits,
                );
                let dismount = data_disk::dismount(self.executor.as_ref(), &mut prepared.data_disk);
                prepared.journal.data_disk = Some(prepared.data_disk.clone());
                prepared.journal.persist()?;
                dismount?;
                let collected = collected?;
                let envelope = collected.result;
                envelope
                    .validate_metadata()
                    .map_err(|error| SandboxError::new("hyperv_result", error.to_string()))?;
                if envelope.run_id != prepared.run_id {
                    return Err(SandboxError::new(
                        "hyperv_result",
                        "guest result run identifier does not match",
                    ));
                }
                validate_guest_result(&envelope, request, &prepared._base.manifest.image_version)?;
                let post_verification =
                    self.network_post_verification.as_mut().ok_or_else(|| {
                        SandboxError::new(
                            "hyperv_network",
                            "post-run host network attestation was not retained",
                        )
                    })?;
                network::bind_guest_attestation(
                    &prepared.network_plan,
                    post_verification,
                    envelope.network_attestation.as_ref(),
                )?;
                let mut result = envelope.execution.ok_or_else(|| {
                    SandboxError::new(
                        "hyperv_result",
                        "guest result did not contain an execution result",
                    )
                })?;
                result.backend = "hyperv".to_string();
                result.stdout = collected.stdout;
                result.stderr = collected.stderr;
                result.monitor_warnings.push(host_observation);
                result.monitor_warnings.extend(envelope.warnings);
                for coverage in [
                    envelope.coverage.stdout,
                    envelope.coverage.stderr,
                    envelope.coverage.processes,
                    envelope.coverage.network,
                    envelope.coverage.filesystem,
                    envelope.coverage.registry,
                ] {
                    result.monitor_warnings.extend(coverage.warnings);
                }
                result.monitor_warnings.extend(collected.warnings);
                if !collected.artifacts.is_empty() {
                    result.monitor_warnings.push(format!(
                        "collected {} bounded guest artifact(s), {} total output bytes",
                        collected.artifacts.len(),
                        collected.total_bytes
                    ));
                }
                result.cleanup = CleanupStatus::pending();
                if result.timed_out
                    && let Some(completion_stage) = execution_stages
                        .iter_mut()
                        .find(|stage| stage.stage == "timeout_or_completion")
                {
                    completion_stage.warnings.push(
                        "the guest agent reported that the target timeout expired; the host VM deadline did not expire"
                            .to_string(),
                    );
                }
                execution_stages.push(artifact_timer.finish(true, Vec::new(), Vec::new()));
                Ok(result)
            }
        }
    }

    fn track_preparation(&mut self, journal: &CleanupJournal) {
        self.prepared = Some(PreparedRun::Preparing(Box::new(journal.clone())));
    }
}

enum VmCompletion {
    PoweredOff(HostVmObservations),
    TimedOut(HostVmObservations),
    DiskQuotaExceeded {
        observed_bytes: u64,
        maximum_bytes: u64,
        observations: HostVmObservations,
    },
}

#[derive(Clone, Copy, Debug)]
struct DiskQuotaBreach {
    observed_bytes: u64,
    maximum_bytes: u64,
}

#[derive(Clone, Copy, Debug)]
struct WritableDiskQuota<'a> {
    os_disk_path: &'a std::path::Path,
    data_disk_path: &'a std::path::Path,
    maximum_os_disk_bytes: u64,
    maximum_total_disk_bytes: u64,
}

#[derive(Clone, Debug, Default)]
struct HostVmObservations {
    maximum_cpu_percent: u16,
    maximum_memory_bytes: u64,
    maximum_uptime_ms: u64,
    heartbeat_enabled: bool,
    heartbeat_healthy_seen: bool,
    latest_heartbeat_primary_status: String,
    latest_heartbeat_secondary_status: String,
}

impl HostVmObservations {
    fn record(&mut self, status: &vm::VmStatus) {
        self.maximum_cpu_percent = self.maximum_cpu_percent.max(status.cpu_usage_percent);
        self.maximum_memory_bytes = self.maximum_memory_bytes.max(status.memory_assigned_bytes);
        self.maximum_uptime_ms = self.maximum_uptime_ms.max(status.uptime_ms);
        self.heartbeat_enabled |= status.heartbeat_enabled;
        self.heartbeat_healthy_seen |= status.heartbeat_primary_status.eq_ignore_ascii_case("ok");
        self.latest_heartbeat_primary_status = status.heartbeat_primary_status.clone();
        self.latest_heartbeat_secondary_status = status.heartbeat_secondary_status.clone();
    }

    fn summary(&self) -> String {
        format!(
            "host VM observations: maximum_cpu_percent={}, maximum_memory_bytes={}, maximum_uptime_ms={}, heartbeat_enabled={}, heartbeat_healthy_seen={}, latest_heartbeat_primary_status={:?}, latest_heartbeat_secondary_status={:?}",
            self.maximum_cpu_percent,
            self.maximum_memory_bytes,
            self.maximum_uptime_ms,
            self.heartbeat_enabled,
            self.heartbeat_healthy_seen,
            self.latest_heartbeat_primary_status,
            self.latest_heartbeat_secondary_status,
        )
    }
}

fn wait_for_vm_completion(
    executor: &dyn PowerShellExecutor,
    vm: &VmHandle,
    timeout: Duration,
    disk_quota: &WritableDiskQuota<'_>,
    maximum_memory_bytes: u64,
) -> SandboxResult<VmCompletion> {
    let stop_watch = AtomicBool::new(false);
    let watch_result: Mutex<Option<SandboxResult<DiskQuotaBreach>>> = Mutex::new(None);
    thread::scope(|scope| {
        let watcher = scope.spawn(|| {
            while !stop_watch.load(Ordering::Acquire) {
                match writable_disk_usage(disk_quota) {
                    Ok(Some(breach)) => {
                        let _ = vm::stop(executor, vm, true);
                        *watch_result.lock().unwrap() = Some(Ok(breach));
                        return;
                    }
                    Ok(None) => {}
                    Err(error) => {
                        let _ = vm::stop(executor, vm, true);
                        *watch_result.lock().unwrap() = Some(Err(error));
                        return;
                    }
                }
                thread::sleep(DISK_QUOTA_WATCH_INTERVAL);
            }
        });

        let observed =
            observe_vm_completion(executor, vm, timeout, disk_quota, maximum_memory_bytes);
        stop_watch.store(true, Ordering::Release);
        let _ = watcher.join();
        let quota = watch_result.lock().unwrap().take();
        match quota {
            Some(Err(error)) => Err(error),
            Some(Ok(breach)) => {
                let observations = match observed {
                    Ok(VmCompletion::PoweredOff(observations))
                    | Ok(VmCompletion::TimedOut(observations))
                    | Ok(VmCompletion::DiskQuotaExceeded { observations, .. }) => observations,
                    Err(_) => HostVmObservations::default(),
                };
                Ok(VmCompletion::DiskQuotaExceeded {
                    observed_bytes: breach.observed_bytes,
                    maximum_bytes: breach.maximum_bytes,
                    observations,
                })
            }
            None => observed,
        }
    })
}

fn observe_vm_completion(
    executor: &dyn PowerShellExecutor,
    vm: &VmHandle,
    timeout: Duration,
    disk_quota: &WritableDiskQuota<'_>,
    maximum_memory_bytes: u64,
) -> SandboxResult<VmCompletion> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(Instant::now);
    let mut observations = HostVmObservations::default();
    loop {
        if crate::interrupt::requested() {
            return Err(SandboxError::new(
                "hyperv_runtime",
                "sandbox run interrupted; cleanup will now run",
            ));
        }
        let status = vm::query(executor, &vm.id)?;
        if !status.exists
            || status.name.as_deref() != Some(vm.name.as_str())
            || status.snapshot_count != 0
            || status.cpu_usage_percent > 100
            || status.memory_assigned_bytes > maximum_memory_bytes
            || status.health.len() > 256
            || status.health.chars().any(char::is_control)
            || status.heartbeat_primary_status.len() > 256
            || status.heartbeat_secondary_status.len() > 256
            || status
                .heartbeat_primary_status
                .chars()
                .any(char::is_control)
            || status
                .heartbeat_secondary_status
                .chars()
                .any(char::is_control)
        {
            return Err(SandboxError::new(
                "hyperv_runtime",
                "VM identity, health, checkpoint, CPU, or memory state violated the run policy",
            ));
        }
        observations.record(&status);
        if status.state.eq_ignore_ascii_case("off") {
            return Ok(VmCompletion::PoweredOff(observations));
        }
        if !matches!(
            status.state.to_ascii_lowercase().as_str(),
            "running" | "starting" | "stopping" | "forceshutdown"
        ) {
            return Err(SandboxError::new(
                "hyperv_runtime",
                format!(
                    "disposable VM entered an unexpected or unhealthy state: {}",
                    status.state
                ),
            ));
        }
        if let Some(breach) = writable_disk_usage(disk_quota)? {
            return Ok(VmCompletion::DiskQuotaExceeded {
                observed_bytes: breach.observed_bytes,
                maximum_bytes: breach.maximum_bytes,
                observations,
            });
        }
        if Instant::now() >= deadline {
            return Ok(VmCompletion::TimedOut(observations));
        }
        thread::sleep(Duration::from_millis(250));
    }
}

fn writable_disk_usage(
    disk_quota: &WritableDiskQuota<'_>,
) -> SandboxResult<Option<DiskQuotaBreach>> {
    let os_bytes = checked_vhd_length(disk_quota.os_disk_path)?;
    let data_bytes = checked_vhd_length(disk_quota.data_disk_path)?;
    let total_bytes = os_bytes.checked_add(data_bytes).ok_or_else(|| {
        SandboxError::new(
            "hyperv_runtime",
            "aggregate writable-disk byte count overflowed",
        )
    })?;
    if os_bytes > disk_quota.maximum_os_disk_bytes {
        Ok(Some(DiskQuotaBreach {
            observed_bytes: os_bytes,
            maximum_bytes: disk_quota.maximum_os_disk_bytes,
        }))
    } else if total_bytes > disk_quota.maximum_total_disk_bytes {
        Ok(Some(DiskQuotaBreach {
            observed_bytes: total_bytes,
            maximum_bytes: disk_quota.maximum_total_disk_bytes,
        }))
    } else {
        Ok(None)
    }
}

fn checked_vhd_length(path: &std::path::Path) -> SandboxResult<u64> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        SandboxError::with_source("hyperv_runtime", "inspect writable VHDX growth", error)
    })?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(SandboxError::new(
            "hyperv_runtime",
            "writable VHDX became a non-regular file or symbolic link",
        ));
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(SandboxError::new(
                "hyperv_runtime",
                "writable VHDX became a reparse point",
            ));
        }
    }
    Ok(metadata.len())
}

fn require_host_free_space(path: &std::path::Path, required_bytes: u64) -> SandboxResult<()> {
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::ffi::OsStrExt;

        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn GetDiskFreeSpaceExW(
                directory_name: *const u16,
                free_bytes_available: *mut u64,
                total_bytes: *mut u64,
                total_free_bytes: *mut u64,
            ) -> i32;
        }

        let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
        wide.push(0);
        let mut available = 0u64;
        let mut total = 0u64;
        let mut total_free = 0u64;
        if unsafe {
            GetDiskFreeSpaceExW(wide.as_ptr(), &mut available, &mut total, &mut total_free)
        } == 0
        {
            return Err(SandboxError::with_source(
                "hyperv_configuration",
                "query free space for the protected Hyper-V run volume",
                std::io::Error::last_os_error(),
            ));
        }
        if available < required_bytes {
            return Err(SandboxError::new(
                "hyperv_configuration",
                format!(
                    "Hyper-V run volume has {available} available bytes but the configured disk budgets require {required_bytes}"
                ),
            ));
        }
        let _ = (total, total_free);
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (path, required_bytes);
    }
    Ok(())
}

struct PartialPreservation {
    message: String,
    success: bool,
}

fn preserve_partial_guest_output(
    executor: &dyn PowerShellExecutor,
    prepared: &mut LivePrepared,
    limits: &CollectionLimits,
    shutdown_grace: Duration,
) -> PartialPreservation {
    let attempt = (|| -> SandboxResult<result_collector::PartialCollection> {
        if !vm::wait_for_off(executor, &prepared.vm, shutdown_grace)? {
            return Err(SandboxError::new(
                "hyperv_partial_collection",
                "VM did not stop within the partial-output collection grace period",
            ));
        }
        vm::detach_disk(executor, &prepared.vm, &prepared.data_disk.path)?;
        data_disk::mount_existing(executor, &mut prepared.data_disk)?;
        prepared.journal.data_disk = Some(prepared.data_disk.clone());
        prepared.journal.persist()?;
        let archive_root = prepared
            .journal
            .run_root
            .join("partial-collected-artifacts");
        let collection = result_collector::collect_partial(
            &prepared
                .data_disk
                .mount_path
                .join(data_disk::RUN_DIRECTORY_NAME),
            &archive_root,
            limits,
        );
        let dismount = data_disk::dismount(executor, &mut prepared.data_disk);
        prepared.journal.data_disk = Some(prepared.data_disk.clone());
        let persist = prepared.journal.persist();
        dismount?;
        persist?;
        collection
    })();
    match attempt {
        Ok(partial) => PartialPreservation {
            message: format!(
                "preserved {} bounded untrusted partial guest output file(s), {} bytes total",
                partial.artifact_count, partial.total_bytes
            ),
            success: true,
        },
        Err(error) => PartialPreservation {
            message: format!("could not preserve partial guest output: {error}"),
            success: false,
        },
    }
}

fn os_disk_quota_error(
    observed_bytes: u64,
    maximum_bytes: u64,
    preservation: &str,
) -> SandboxError {
    SandboxError::new(
        "hyperv_os_disk_quota",
        format!(
            "critical containment event: disposable VM writable disks reached {observed_bytes} bytes and exceeded the {maximum_bytes} byte aggregate host quota; {preservation}"
        ),
    )
}

fn build_guest_request(
    request: &SandboxRequest,
    network_plan: &HyperVNetworkPlan,
    run_id: &str,
    target_sha256: Option<String>,
) -> SandboxResult<GuestRunRequest> {
    let (network_policy, allowed_networks) = match &request.network_policy {
        NetworkPolicy::DenyAll => (GuestNetworkPolicy::DenyAll, Vec::new()),
        NetworkPolicy::HostServer => (GuestNetworkPolicy::HostServer, Vec::new()),
        NetworkPolicy::AllowList(entries) => (
            GuestNetworkPolicy::AllowList,
            entries.iter().map(ToString::to_string).collect(),
        ),
        NetworkPolicy::AllowInternet => (GuestNetworkPolicy::AllowInternet, Vec::new()),
        NetworkPolicy::CaptureOnly => (GuestNetworkPolicy::CaptureOnly, Vec::new()),
    };
    let (
        guest_ipv4,
        prefix_length,
        gateway_ipv4,
        dns_servers,
        host_service_ipv4,
        host_service_port,
    ) = network::guest_configuration(network_plan);
    let mitigation_profile = match request.mitigation_profile {
        MitigationProfile::Compatible => GuestMitigationProfile::Compatible,
        MitigationProfile::Strict => GuestMitigationProfile::Strict,
        MitigationProfile::Maximum => GuestMitigationProfile::Maximum,
    };
    let guest_request = GuestRunRequest {
        protocol_version: PROTOCOL_VERSION,
        run_id: run_id.to_string(),
        target: data_disk::guest_target_path(&request.target).to_string(),
        target_sha256,
        arguments: request.arguments.clone(),
        timeout_seconds: request.timeout_secs,
        network_policy,
        allowed_networks,
        guest_ipv4,
        prefix_length,
        gateway_ipv4,
        dns_servers,
        host_service_ipv4,
        host_service_port,
        mitigation_profile,
        execution_profile: match request.hyperv_guest_profile {
            crate::sandbox::backend::HyperVGuestProfile::Restricted => {
                GuestExecutionProfile::Restricted
            }
            crate::sandbox::backend::HyperVGuestProfile::Normal => GuestExecutionProfile::Normal,
            crate::sandbox::backend::HyperVGuestProfile::Admin => GuestExecutionProfile::Admin,
        },
        resource_limits: GuestResourceLimits {
            active_process_limit: request.resource_limits.active_process_limit,
            process_memory_bytes: request.resource_limits.process_memory_bytes as u64,
            job_memory_bytes: request.resource_limits.job_memory_bytes as u64,
            cpu_rate_percent: request.resource_limits.cpu_rate_percent,
        },
        capture: CaptureOptions::default(),
        shutdown_when_complete: true,
    };
    guest_request
        .validate()
        .map_err(|error| SandboxError::new("hyperv_guest_request", error.to_string()))?;
    Ok(guest_request)
}

fn validate_guest_result(
    envelope: &GuestResultEnvelope<SandboxRunResult>,
    request: &SandboxRequest,
    expected_guest_image_version: &str,
) -> SandboxResult<()> {
    if envelope.guest_image_version != expected_guest_image_version {
        return Err(SandboxError::new(
            "hyperv_result",
            "guest result image version does not match the pinned base-image manifest",
        ));
    }
    let execution = match envelope.outcome {
        GuestTerminalOutcome::AgentFailed => {
            let error = envelope.error.as_ref().ok_or_else(|| {
                SandboxError::new(
                    "hyperv_result",
                    "guest agent failed without an error record",
                )
            })?;
            return Err(SandboxError::new(
                "hyperv_guest_agent",
                format!("{}:{}: {}", error.stage, error.code, error.message),
            ));
        }
        GuestTerminalOutcome::Cancelled => {
            return Err(SandboxError::new(
                "hyperv_guest_agent",
                "guest execution was cancelled before producing a sandbox result",
            ));
        }
        GuestTerminalOutcome::Completed | GuestTerminalOutcome::TimedOut => {
            envelope.execution.as_ref().ok_or_else(|| {
                SandboxError::new(
                    "hyperv_result",
                    "terminal guest outcome omitted its execution result",
                )
            })?
        }
    };
    let expected_timed_out = envelope.outcome == GuestTerminalOutcome::TimedOut;
    let (expected_backend, expected_integrity) = match request.hyperv_guest_profile {
        crate::sandbox::backend::HyperVGuestProfile::Restricted => (
            "restricted_process",
            if request.mitigation_profile == MitigationProfile::Maximum {
                "untrusted"
            } else {
                "low"
            },
        ),
        crate::sandbox::backend::HyperVGuestProfile::Normal => ("guest_native", "medium"),
        crate::sandbox::backend::HyperVGuestProfile::Admin => ("guest_native", "system"),
    };
    if execution.backend != expected_backend
        || execution.network_policy != request.network_policy.name()
        || execution.mitigation_profile != request.mitigation_profile.to_string()
        || execution.integrity_level != expected_integrity
        || execution.timed_out != expected_timed_out
        || !execution.mapped_paths.is_empty()
        || execution.cleanup.leftover_resources.len() > 128
        || execution.cleanup.warnings.len() > 256
    {
        return Err(SandboxError::new(
            "hyperv_result",
            "guest execution metadata contradicts the authenticated host request",
        ));
    }
    if !execution.cleanup.attempted {
        return Err(SandboxError::new(
            "hyperv_result",
            "guest process cleanup was not attempted",
        ));
    }
    for capture in [&execution.stdout_capture, &execution.stderr_capture] {
        if capture.bytes_stored > capture.bytes_seen
            || (!capture.truncated && capture.bytes_stored != capture.bytes_seen)
        {
            return Err(SandboxError::new(
                "hyperv_result",
                "guest stream capture summary is internally inconsistent",
            ));
        }
    }
    let maximum_observations = 100_000usize;
    if execution.processes.len() > maximum_observations
        || execution.network_connections.len() > maximum_observations
        || execution.file_observations.len() > maximum_observations
        || execution.registry_observations.len() > maximum_observations
        || execution.monitor_warnings.len() > 4_096
    {
        return Err(SandboxError::new(
            "hyperv_result",
            "guest result contains an unreasonable observation or warning count",
        ));
    }
    for observation in &execution.file_observations {
        if observation.relative_path.is_empty()
            || observation.relative_path.len() > 4_096
            || observation.relative_path.contains('\0')
            || observation.kind.is_empty()
            || observation.kind.len() > 128
            || observation.kind.contains('\0')
        {
            return Err(SandboxError::new(
                "hyperv_result",
                "guest result contains an invalid file observation",
            ));
        }
        if let Some(digest) = observation.sha256.as_deref() {
            crate::sandbox::hyperv::guest_protocol::validate_sha256(digest).map_err(|_| {
                SandboxError::new(
                    "hyperv_result",
                    "guest result contains an invalid file-observation SHA-256",
                )
            })?;
        }
        if observation
            .hash_source
            .as_deref()
            .is_some_and(|source| source.is_empty() || source.len() > 128 || source.contains('\0'))
        {
            return Err(SandboxError::new(
                "hyperv_result",
                "guest result contains an invalid file hash source",
            ));
        }
        if observation.sha256.is_none() && observation.hash_source.is_some() {
            return Err(SandboxError::new(
                "hyperv_result",
                "guest result names a file hash source without a digest",
            ));
        }
    }
    validate_coverage_binding(&envelope.coverage)?;
    Ok(())
}

fn validate_coverage_binding(coverage: &ObservationCoverage) -> SandboxResult<()> {
    for (name, item) in [
        ("stdout", &coverage.stdout),
        ("stderr", &coverage.stderr),
        ("process", &coverage.processes),
        ("network", &coverage.network),
        ("filesystem", &coverage.filesystem),
        ("registry", &coverage.registry),
    ] {
        if !item.requested {
            return Err(SandboxError::new(
                "hyperv_result",
                format!("guest result says requested {name} capture was not requested"),
            ));
        }
        if !item.collected && item.warnings.is_empty() {
            return Err(SandboxError::new(
                "hyperv_result",
                format!("unavailable {name} capture has no limitation warning"),
            ));
        }
    }
    Ok(())
}

fn pinned_input_path(file: &File, requested: &std::path::Path) -> std::io::Result<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        let _ = requested;
        artifact::final_path_by_handle(file)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = file;
        requested.canonicalize()
    }
}

fn hash_pinned_target(file: &mut File, expected_len: u64) -> SandboxResult<String> {
    file.seek(SeekFrom::Start(0)).map_err(|error| {
        SandboxError::with_source(
            "hyperv_prepare",
            "rewind pinned target before hashing",
            error,
        )
    })?;
    let mut hasher = Sha256::new();
    let copied = std::io::copy(
        &mut std::io::Read::by_ref(file).take(expected_len.saturating_add(1)),
        &mut hasher,
    )
    .map_err(|error| {
        SandboxError::with_source("hyperv_prepare", "hash the pinned target bytes", error)
    })?;
    file.seek(SeekFrom::Start(0)).map_err(|error| {
        SandboxError::with_source(
            "hyperv_prepare",
            "rewind pinned target after hashing",
            error,
        )
    })?;
    if copied != expected_len {
        return Err(SandboxError::new(
            "hyperv_prepare",
            "target changed while its integrity hash was calculated",
        ));
    }
    Ok(format!("{:x}", hasher.finalize()))
}

enum SyntheticOutcome {
    DryRun,
    HostVmTimeout,
}

fn synthetic_result(
    request: &SandboxRequest,
    outcome: SyntheticOutcome,
    elapsed: Duration,
) -> SandboxRunResult {
    let empty_capture = || StreamCaptureSummary {
        bytes_seen: 0,
        bytes_stored: 0,
        truncated: false,
    };
    let (timed_out, warning) = match outcome {
        SyntheticOutcome::DryRun => (
            false,
            "dry-run: the target and Hyper-V configuration were validated, but no VM was created and the target was not executed",
        ),
        SyntheticOutcome::HostVmTimeout => (
            true,
            "the authoritative host VM deadline expired before authenticated guest completion",
        ),
    };
    SandboxRunResult {
        backend: "hyperv".to_string(),
        network_policy: request.network_policy.name().to_string(),
        integrity_level: "guest_non_admin".to_string(),
        mitigation_profile: request.mitigation_profile.to_string(),
        pid: 0,
        exit_code: None,
        timed_out,
        working_dir: None,
        duration_ms: elapsed.as_millis().min(u64::MAX as u128) as u64,
        stdout: String::new(),
        stderr: String::new(),
        stdout_capture: empty_capture(),
        stderr_capture: empty_capture(),
        processes: Vec::new(),
        network_connections: Vec::new(),
        file_observations: Vec::new(),
        registry_observations: Vec::new(),
        mapped_paths: Vec::new(),
        monitor_warnings: vec![warning.to_string()],
        cleanup: CleanupStatus::pending(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guest_request_uses_only_guest_relative_paths() {
        let request = SandboxRequest::hyperv("sample.exe");
        let guest = build_guest_request(
            &request,
            &HyperVNetworkPlan::DenyAll,
            "0123456789abcdef",
            Some("a".repeat(64)),
        )
        .unwrap();
        assert_eq!(guest.target, "input/target.bin");
        assert!(guest.shutdown_when_complete);
        let encoded = serde_json::to_string(&guest).unwrap();
        assert!(!encoded.contains("sample.exe"));
    }

    #[test]
    fn guest_request_preserves_approved_batch_extension() {
        let request = SandboxRequest::hyperv("sample.CMD");
        let guest = build_guest_request(
            &request,
            &HyperVNetworkPlan::DenyAll,
            "0123456789abcdef",
            Some("a".repeat(64)),
        )
        .unwrap();
        assert_eq!(guest.target, "input/target.cmd");
        assert!(!guest.target.contains("sample"));
    }

    #[test]
    fn guest_request_authenticates_each_execution_profile() {
        for (host, guest_profile) in [
            (
                crate::sandbox::backend::HyperVGuestProfile::Restricted,
                GuestExecutionProfile::Restricted,
            ),
            (
                crate::sandbox::backend::HyperVGuestProfile::Normal,
                GuestExecutionProfile::Normal,
            ),
            (
                crate::sandbox::backend::HyperVGuestProfile::Admin,
                GuestExecutionProfile::Admin,
            ),
        ] {
            let mut request = SandboxRequest::hyperv("sample.exe");
            request.hyperv_guest_profile = host;
            let guest = build_guest_request(
                &request,
                &HyperVNetworkPlan::DenyAll,
                "0123456789abcdef",
                Some("a".repeat(64)),
            )
            .unwrap();
            assert_eq!(guest.execution_profile, guest_profile);
        }
    }

    #[test]
    fn os_disk_quota_is_a_typed_execution_error() {
        let error = os_disk_quota_error(
            2 * 1024 * 1024,
            1024 * 1024,
            "preserved 1 bounded untrusted partial guest output file(s), 64 bytes total",
        );
        assert_eq!(error.stage, "hyperv_os_disk_quota");
        assert!(error.message.contains("exceeded"));
        assert!(error.message.contains("preserved 1"));
    }

    #[test]
    fn writable_disk_budget_is_five_gibibytes_in_aggregate() {
        let config = HyperVConfig {
            base_image_path: std::env::temp_dir().join("base.vhdx"),
            base_manifest_path: std::env::temp_dir().join("base.json"),
            run_root: std::env::temp_dir().join("foxhole-quota-config"),
            processor_count: 2,
            startup_memory_bytes: 2 * 1024 * 1024 * 1024,
            data_disk_bytes: DEFAULT_DATA_DISK_BYTES,
            maximum_os_disk_growth_bytes: DEFAULT_OS_DISK_GROWTH_BYTES,
            boot_timeout_secs: 120,
            shutdown_grace_secs: 15,
            controlled_gateway: None,
            collection_limits: CollectionLimits::default(),
        };
        assert_eq!(
            config.data_disk_bytes + config.maximum_os_disk_growth_bytes,
            MAX_VM_WRITABLE_DISK_BYTES
        );
        assert!(config.validate().is_ok());

        let mut oversized = config;
        oversized.maximum_os_disk_growth_bytes += 1;
        assert!(oversized.validate().is_err());
    }

    #[test]
    fn aggregate_writable_disk_usage_counts_both_vhdx_files() {
        let root = std::env::temp_dir().join(format!(
            "foxhole-quota-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        let os_disk = root.join("os-diff.vhdx");
        let data_disk = root.join("run-data.vhdx");
        std::fs::File::create(&os_disk).unwrap().set_len(6).unwrap();
        std::fs::File::create(&data_disk)
            .unwrap()
            .set_len(5)
            .unwrap();

        let disk_quota = WritableDiskQuota {
            os_disk_path: &os_disk,
            data_disk_path: &data_disk,
            maximum_os_disk_bytes: 10,
            maximum_total_disk_bytes: 10,
        };
        let breach = writable_disk_usage(&disk_quota)
            .unwrap()
            .expect("combined files exceed the aggregate limit");
        assert_eq!(breach.observed_bytes, 11);
        assert_eq!(breach.maximum_bytes, 10);

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn synthetic_results_never_claim_a_successful_exit() {
        let request = SandboxRequest::hyperv("sample.exe");
        let dry_run =
            synthetic_result(&request, SyntheticOutcome::DryRun, Duration::from_millis(2));
        assert_eq!(dry_run.exit_code, None);
        assert!(!dry_run.timed_out);
        assert!(
            dry_run
                .monitor_warnings
                .iter()
                .any(|warning| warning.contains("not executed"))
        );

        let host_timeout = synthetic_result(
            &request,
            SyntheticOutcome::HostVmTimeout,
            Duration::from_millis(2),
        );
        assert_eq!(host_timeout.exit_code, None);
        assert!(host_timeout.timed_out);
        assert!(
            host_timeout
                .monitor_warnings
                .iter()
                .any(|warning| warning.contains("host VM deadline"))
        );
    }
}
