#[cfg_attr(target_os = "linux", path = "loserland_exec/linux.rs")]
#[cfg_attr(windows, path = "loserland_exec/windows.rs")]
pub mod loserland_exec;
