#![cfg(target_os = "linux")]

use crate::structs::UserNixFlags;
use nix::Error;
use nix::libc::setgid;
use nix::sched::{CloneFlags, unshare};
use nix::sys::wait::waitpid;
use nix::unistd::{ForkResult, Gid, Uid, execvp, fork, setpgid, setuid};
use std::ffi::CString;
use std::process::exit;
/// Starts a process in a new namespace with the specified isolation flags.
///
/// # Safety
/// This function requires root privileges to work properly.
/// Calling this function may affect the entire process's namespace visibility.
///
/// # Arguments
/// * `file` - Path to the file to execute in the sandbox
/// * `flags` - Namespace isolation flags
///
/// # Returns
/// Result indicating success or specific error condition

fn convert_flags(flags: &UserNixFlags) -> CloneFlags {
    match flags {
        UserNixFlags::USR_SHARE_VM => nix::sched::CloneFlags::CLONE_VM,
        UserNixFlags::USR_SHARE_FS => nix::sched::CloneFlags::CLONE_FS,
        UserNixFlags::USR_SHARE_FILES => nix::sched::CloneFlags::CLONE_FILES,
        UserNixFlags::USR_SHARE_SIG => nix::sched::CloneFlags::CLONE_SIGHAND,
        UserNixFlags::USR_ALLOW_TRACE => nix::sched::CloneFlags::CLONE_PTRACE,
        UserNixFlags::USR_PARENT_WAIT => nix::sched::CloneFlags::CLONE_VFORK,
        UserNixFlags::USR_SAME_PARENT => nix::sched::CloneFlags::CLONE_PARENT,
        UserNixFlags::USR_THREAD => nix::sched::CloneFlags::CLONE_THREAD,
        UserNixFlags::USR_NEW_MOUNT => nix::sched::CloneFlags::CLONE_NEWNS,
        UserNixFlags::USR_SHARE_SEMAPHORE => nix::sched::CloneFlags::CLONE_SYSVSEM,
        UserNixFlags::USR_NO_TRACE => nix::sched::CloneFlags::CLONE_UNTRACED,
        UserNixFlags::USR_NEW_CGROUP => nix::sched::CloneFlags::CLONE_NEWCGROUP,
        UserNixFlags::USR_NEW_HOSTNAME => nix::sched::CloneFlags::CLONE_NEWUTS,
        UserNixFlags::USR_NEW_IPC => nix::sched::CloneFlags::CLONE_NEWIPC,
        UserNixFlags::USR_NEW_USER => nix::sched::CloneFlags::CLONE_NEWUSER,
        UserNixFlags::USR_NEW_PID => nix::sched::CloneFlags::CLONE_NEWPID,
        UserNixFlags::USR_NEW_NET => nix::sched::CloneFlags::CLONE_NEWNET,
        UserNixFlags::USR_SHARE_IO => nix::sched::CloneFlags::CLONE_IO,
    }
}

pub fn start_in_sandbox(file: &str, flags: Vec<UserNixFlags>) -> Result<(), nix::Error> {
    let mut clone_flags = CloneFlags::empty();
    for flag in flags.iter() {
        clone_flags |= convert_flags(flag);
    }

    if let Err(err) = unshare(clone_flags) {
        match err {
            nix::errno::Errno::EACCES => {
                eprintln!(
                    "[sandbox] Error: Insufficient permissions to unshare namespaces. Try running as root."
                );
            }
            nix::errno::Errno::EINVAL => {
                eprintln!("[sandbox] Error: Invalid flags provided for unshare.");
            }
            _ => {
                eprintln!("[sandbox] Error: {}", err);
            }
        }
        // exit proces if namespaces are not created successfully
        return Err(err);
    }

    match unsafe { fork()? } {
        ForkResult::Parent { child } => {
            println!("[sandbox] Parent process, waiting for child...");
            waitpid(child, None).expect("Failed to wait for child process");
            println!("[sandbox] Child process exited!");
        }
        ForkResult::Child => {
            println!("[sandbox] Inside child process!");
            // Set the UID and GID to nobody
            let nobody_uid = Uid::from_raw(65534); // UID for 'nobody'
            let nobody_gid = Gid::from_raw(65534); // GID for 'nobody'

            unsafe {
                let r_sgid = setgid(nobody_gid.as_raw());
                if let Err(err) = r_sgid {
                    eprintln!("[sandbox] Error: Failed to set GID: {}", err);
                    std::process::exit(-9);
                }
            }
            setuid(nobody_uid).expect("Failed to set UID");

            let cmd = CString::new(file).unwrap();
            let args = [cmd.clone()].to_vec();
            execvp(&cmd, &args).expect("Failed to exec");
            exit(1); // This line will not be reached if execvp is successful
        } // issues:
          // cat /etc/sudoers should return permission denied but is readable as nobody
          // cd /tmp is blocked but should be allowed?
    }

    Ok(())
}

// TODO: make sure sandbox is safe
