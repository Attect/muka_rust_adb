use std::mem;
use std::ptr;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{SyncSender, sync_channel};
use std::thread;

use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DispatchMessageW, GetMessageW, MSG, PBT_APMRESUMEAUTOMATIC,
    RegisterClassExW, TranslateMessage, WM_POWERBROADCAST, WNDCLASSEXW, WS_EX_NOACTIVATE, WS_POPUP,
};

use crate::error::{AdbError, Result};

static RESUME_GENERATION: AtomicU64 = AtomicU64::new(0);
static POWER_MONITOR: OnceLock<std::result::Result<(), String>> = OnceLock::new();

const POWER_WINDOW_CLASS: &[u16] = &[
    'A' as u16, 'd' as u16, 'b' as u16, 'R' as u16, 'u' as u16, 's' as u16, 't' as u16, 'P' as u16,
    'o' as u16, 'w' as u16, 'e' as u16, 'r' as u16, 'W' as u16, 'i' as u16, 'n' as u16, 'd' as u16,
    'o' as u16, 'w' as u16, 0,
];
const POWER_WINDOW_TITLE: &[u16] = &[
    'A' as u16, 'D' as u16, 'B' as u16, ' ' as u16, 'P' as u16, 'o' as u16, 'w' as u16, 'e' as u16,
    'r' as u16, ' ' as u16, 'N' as u16, 'o' as u16, 't' as u16, 'i' as u16, 'f' as u16, 'i' as u16,
    'c' as u16, 'a' as u16, 't' as u16, 'i' as u16, 'o' as u16, 'n' as u16, ' ' as u16, 'W' as u16,
    'i' as u16, 'n' as u16, 'd' as u16, 'o' as u16, 'w' as u16, 0,
];

unsafe extern "system" fn power_window_proc(
    hwnd: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    if is_automatic_resume_message(message, wparam) {
        RESUME_GENERATION.fetch_add(1, Ordering::SeqCst);
        return 1;
    }
    unsafe { DefWindowProcW(hwnd, message, wparam, lparam) }
}

fn is_automatic_resume_message(message: u32, wparam: WPARAM) -> bool {
    message == WM_POWERBROADCAST && wparam == PBT_APMRESUMEAUTOMATIC as WPARAM
}

fn launch_power_monitor() -> std::result::Result<(), String> {
    let (ready_tx, ready_rx) = sync_channel(1);
    thread::Builder::new()
        .name("adb-power-notifier".to_string())
        .spawn(move || power_notification_thread(ready_tx))
        .map_err(|err| format!("无法启动 power notification thread: {err}"))?;
    ready_rx
        .recv()
        .map_err(|_| "power notification thread 在窗口就绪前退出".to_string())?
}

fn power_notification_thread(ready_tx: SyncSender<std::result::Result<(), String>>) {
    let result = create_power_window();
    if let Err(err) = &result {
        let _ = ready_tx.send(Err(err.clone()));
        return;
    }
    if ready_tx.send(Ok(())).is_err() {
        return;
    }

    let mut message = unsafe { mem::zeroed::<MSG>() };
    loop {
        let status = unsafe { GetMessageW(&mut message, ptr::null_mut(), 0, 0) };
        if status <= 0 {
            return;
        }
        unsafe {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }
}

fn create_power_window() -> std::result::Result<(), String> {
    let instance = unsafe { GetModuleHandleW(ptr::null()) };
    if instance.is_null() {
        return Err(format!(
            "GetModuleHandleW failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    let window_class = WNDCLASSEXW {
        cbSize: mem::size_of::<WNDCLASSEXW>() as u32,
        style: 0,
        lpfnWndProc: Some(power_window_proc),
        cbClsExtra: 0,
        cbWndExtra: 0,
        hInstance: instance,
        hIcon: ptr::null_mut(),
        hCursor: ptr::null_mut(),
        hbrBackground: ptr::null_mut(),
        lpszMenuName: ptr::null(),
        lpszClassName: POWER_WINDOW_CLASS.as_ptr(),
        hIconSm: ptr::null_mut(),
    };
    if unsafe { RegisterClassExW(&window_class) } == 0 {
        return Err(format!(
            "RegisterClassExW failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    let window = unsafe {
        CreateWindowExW(
            WS_EX_NOACTIVATE,
            POWER_WINDOW_CLASS.as_ptr(),
            POWER_WINDOW_TITLE.as_ptr(),
            WS_POPUP,
            0,
            0,
            0,
            0,
            ptr::null_mut(),
            ptr::null_mut(),
            instance,
            ptr::null(),
        )
    };
    if window.is_null() {
        return Err(format!(
            "CreateWindowExW failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

pub(super) fn start() -> Result<()> {
    match POWER_MONITOR.get_or_init(launch_power_monitor) {
        Ok(()) => Ok(()),
        Err(err) => Err(AdbError::Server(format!(
            "无法监听 Windows suspend/resume: {err}"
        ))),
    }
}

pub(super) fn resume_generation() -> u64 {
    RESUME_GENERATION.load(Ordering::SeqCst)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_automatic_resume_power_message_kicks_usb_generation() {
        assert!(is_automatic_resume_message(
            WM_POWERBROADCAST,
            PBT_APMRESUMEAUTOMATIC as WPARAM
        ));
        assert!(!is_automatic_resume_message(
            WM_POWERBROADCAST,
            PBT_APMRESUMEAUTOMATIC as WPARAM + 1
        ));
        assert!(!is_automatic_resume_message(
            WM_POWERBROADCAST + 1,
            PBT_APMRESUMEAUTOMATIC as WPARAM
        ));
    }

    #[test]
    fn power_monitor_registration_is_idempotent_and_ready() {
        start().unwrap();
        start().unwrap();
    }
}
