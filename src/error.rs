use std::fmt::{self, Display};
use std::io;

pub type Result<T> = std::result::Result<T, AdbError>;

#[derive(Debug)]
pub enum AdbError {
    Io(io::Error),
    Protocol(String),
    Server(String),
    /// AOSP adb_connect 将 server/device service 的 FAIL 作为 `error:` 输出。
    Client(String),
    /// AOSP SyncConnection 的错误固定使用 `adb: error:` 前缀。
    FileSync(String),
    Usage(String),
    Unsupported(String),
    SilentExit(i32),
}

impl AdbError {
    pub fn exit_code(&self) -> i32 {
        match self {
            AdbError::SilentExit(code) => *code,
            _ => 1,
        }
    }

    pub fn should_print(&self) -> bool {
        !matches!(self, AdbError::SilentExit(_))
    }
}

impl Display for AdbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AdbError::Io(err) => write!(f, "{err}"),
            AdbError::Protocol(msg) => write!(f, "protocol fault: {msg}"),
            AdbError::Server(msg) => write!(f, "{msg}"),
            AdbError::Client(msg) => write!(f, "{msg}"),
            AdbError::FileSync(msg) => write!(f, "{msg}"),
            AdbError::Usage(msg) => write!(f, "{msg}"),
            AdbError::Unsupported(msg) => write!(f, "暂未支持: {msg}"),
            AdbError::SilentExit(code) => write!(f, "remote process exited with status {code}"),
        }
    }
}

impl std::error::Error for AdbError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            AdbError::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for AdbError {
    fn from(value: io::Error) -> Self {
        AdbError::Io(value)
    }
}

#[cfg(test)]
mod tests {
    use super::AdbError;

    #[test]
    fn printable_errors_exit_with_official_failure_code() {
        assert_eq!(AdbError::Usage("bad args".to_string()).exit_code(), 1);
        assert_eq!(AdbError::Server("bad server".to_string()).exit_code(), 1);
        assert_eq!(AdbError::Client("bad client".to_string()).exit_code(), 1);
        assert_eq!(AdbError::FileSync("bad sync".to_string()).exit_code(), 1);
        assert_eq!(AdbError::Unsupported("todo".to_string()).exit_code(), 1);
    }

    #[test]
    fn silent_exit_preserves_requested_code() {
        assert_eq!(AdbError::SilentExit(42).exit_code(), 42);
        assert!(!AdbError::SilentExit(1).should_print());
    }
}
