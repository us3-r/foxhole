use crate::filesystem::ensure_plain_directory;
use crate::runner::{AgentError, AgentResult};
use crate::security;
use foxhole::sandbox::hyperv::guest_protocol::{
    GuestRunRequest, MAX_REQUEST_BYTES, read_bounded_json, wire_path_to_native,
};
use std::path::{Component, Path, PathBuf};

#[derive(Clone, Debug)]
pub struct RunLayout {
    pub root: PathBuf,
    pub request: PathBuf,
    pub input: PathBuf,
    pub output: PathBuf,
    pub status: PathBuf,
}

impl RunLayout {
    pub fn open(root: &Path) -> AgentResult<Self> {
        if !root.is_absolute()
            || root
                .components()
                .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
        {
            return Err(AgentError::new(
                "request",
                "invalid_run_root",
                "run-data root must be absolute and lexically normalized",
            ));
        }
        security::validate_existing_directory_tree(root)?;
        ensure_plain_directory(root)?;
        let canonical = root.canonicalize().map_err(|error| {
            AgentError::with_source(
                "request",
                "canonicalize_run_root",
                "canonicalize the run-data root",
                error,
            )
        })?;

        let layout = Self {
            root: canonical.clone(),
            request: canonical.join("request.json"),
            input: canonical.join("input"),
            output: canonical.join("output"),
            status: canonical.join("status"),
        };
        for directory in [&layout.input, &layout.output, &layout.status] {
            ensure_plain_directory(directory)?;
        }
        security::harden_run_data_layout(
            &layout.root,
            &layout.request,
            &layout.input,
            &layout.output,
            &layout.status,
        )?;
        Ok(layout)
    }

    pub fn load_request(&self) -> AgentResult<GuestRunRequest> {
        let request = read_bounded_json::<GuestRunRequest>(&self.request, MAX_REQUEST_BYTES)
            .map_err(|error| {
                AgentError::new(
                    "request",
                    "invalid_request_json",
                    format!("read and parse request.json: {error}"),
                )
            })?;
        request.validate().map_err(|error| {
            AgentError::new(
                "request",
                "invalid_request",
                format!("validate request.json: {error}"),
            )
        })?;
        let target = self.target_source(&request)?;
        let metadata = target.symlink_metadata().map_err(|error| {
            AgentError::with_source(
                "request",
                "inspect_target",
                "inspect the requested target",
                error,
            )
        })?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(AgentError::new(
                "request",
                "invalid_target",
                "requested target is not a plain regular file",
            ));
        }
        security::harden_broker_file(&target, false)?;
        Ok(request)
    }

    pub fn target_source(&self, request: &GuestRunRequest) -> AgentResult<PathBuf> {
        let target = wire_path_to_native(&self.root, &request.target).map_err(|error| {
            AgentError::new(
                "request",
                "invalid_target_path",
                format!("resolve target path: {error}"),
            )
        })?;
        if !target.starts_with(&self.input) {
            return Err(AgentError::new(
                "request",
                "target_outside_input",
                "requested target escaped the input directory",
            ));
        }
        Ok(target)
    }
}
