pub mod app_processes;
pub mod auth;
pub mod cli;
pub mod client;
pub mod device_tracker;
pub mod error;
pub mod fastdeploy;
pub mod incremental;
pub mod mdns;
pub mod pairing;
pub mod protocol;
pub mod server;
pub mod server_status;
pub mod sync;
pub mod transport;
pub mod usb;

#[cfg(windows)]
pub(crate) mod windows_console;

#[cfg(test)]
pub(crate) mod test_adbd;

#[cfg(test)]
pub(crate) mod test_sync_adbd;

pub use error::{AdbError, Result};

pub fn run() -> Result<()> {
    cli::run(std::env::args().skip(1).collect())
}
