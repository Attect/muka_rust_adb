fn main() {
    if let Err(err) = adb_rust::run() {
        if err.should_print() {
            match &err {
                adb_rust::AdbError::Client(message) => eprintln!("error: {message}"),
                adb_rust::AdbError::FileSync(message) => eprintln!("adb: error: {message}"),
                _ => eprintln!("{}: {err}", program_name()),
            }
        }
        std::process::exit(err.exit_code());
    }
}

fn program_name() -> String {
    program_name_from(std::env::args_os().next())
}

fn program_name_from(path: Option<std::ffi::OsString>) -> String {
    path.and_then(|path| {
        std::path::PathBuf::from(path)
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
    })
    .filter(|name| !name.is_empty())
    .unwrap_or_else(|| "adb".to_string())
}

#[cfg(test)]
mod tests {
    use super::program_name_from;
    use std::ffi::OsString;

    #[test]
    fn program_name_uses_executable_file_name_for_error_prefix() {
        assert_eq!(program_name_from(Some(OsString::from("adb"))), "adb");
        assert_eq!(
            program_name_from(Some(OsString::from("adb.exe"))),
            "adb.exe"
        );
    }

    #[test]
    fn program_name_falls_back_to_adb_when_argv_is_missing() {
        assert_eq!(program_name_from(None), "adb");
    }
}
