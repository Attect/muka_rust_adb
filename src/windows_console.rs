use std::collections::VecDeque;
use std::io::{self, Read};

use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Console::{
    CAPSLOCK_ON, ENHANCED_KEY, GetConsoleMode, GetStdHandle, INPUT_RECORD, KEY_EVENT,
    LEFT_ALT_PRESSED, LEFT_CTRL_PRESSED, NUMLOCK_ON, RIGHT_ALT_PRESSED, RIGHT_CTRL_PRESSED,
    ReadConsoleInputW, SHIFT_PRESSED, STD_INPUT_HANDLE,
};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
    MAPVK_VK_TO_CHAR, MapVirtualKeyW, ToUnicode, VK_BACK, VK_CLEAR, VK_DECIMAL, VK_DELETE,
    VK_DIVIDE, VK_DOWN, VK_END, VK_F1, VK_F2, VK_F3, VK_F4, VK_F5, VK_F6, VK_F7, VK_F8, VK_F9,
    VK_F10, VK_F11, VK_F12, VK_F13, VK_F14, VK_F15, VK_F16, VK_F17, VK_F18, VK_F19, VK_F20,
    VK_HOME, VK_INSERT, VK_LEFT, VK_MULTIPLY, VK_NEXT, VK_NUMPAD0, VK_NUMPAD9, VK_OEM_1, VK_OEM_2,
    VK_OEM_3, VK_OEM_4, VK_OEM_5, VK_OEM_6, VK_OEM_7, VK_OEM_102, VK_OEM_COMMA, VK_OEM_MINUS,
    VK_OEM_PERIOD, VK_OEM_PLUS, VK_PRIOR, VK_RETURN, VK_RIGHT, VK_SPACE, VK_SUBTRACT, VK_TAB,
    VK_UP,
};

const ESC: u8 = 0x1b;
const REPLACEMENT_CHARACTER: &[u8] = "\u{fffd}".as_bytes();

#[derive(Debug, Clone, Copy)]
struct ConsoleKeyEvent {
    repeat_count: u16,
    virtual_key: u16,
    scan_code: u16,
    unicode_char: u16,
    control_state: u32,
}

#[derive(Debug)]
enum InputUnit {
    Bytes(Vec<u8>),
    Utf16(u16),
}

/// 把 Windows 控制台按键转换为 AOSP shell 使用的类 xterm 字节流。
pub(crate) struct WindowsConsoleInput {
    handle: HANDLE,
    buffered: VecDeque<u8>,
    pending_high_surrogate: Option<u16>,
}

impl WindowsConsoleInput {
    pub(crate) fn open() -> io::Result<Self> {
        let handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }

        let mut mode = 0;
        if unsafe { GetConsoleMode(handle, &mut mode) } == 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(Self {
            handle,
            buffered: VecDeque::new(),
            pending_high_surrogate: None,
        })
    }

    fn read_key_event(&self) -> io::Result<ConsoleKeyEvent> {
        loop {
            let mut record: INPUT_RECORD = unsafe { std::mem::zeroed() };
            let mut read = 0;
            if unsafe { ReadConsoleInputW(self.handle, &mut record, 1, &mut read) } == 0 {
                return Err(io::Error::last_os_error());
            }
            if read != 1 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "ReadConsoleInputW 未返回单个输入记录",
                ));
            }
            if u32::from(record.EventType) != KEY_EVENT {
                continue;
            }

            let key = unsafe { record.Event.KeyEvent };
            let unicode_char = unsafe { key.uChar.UnicodeChar };
            if !should_accept_key_record(key.bKeyDown != 0, key.wRepeatCount, unicode_char) {
                continue;
            }
            return Ok(ConsoleKeyEvent {
                repeat_count: key.wRepeatCount,
                virtual_key: key.wVirtualKeyCode,
                scan_code: key.wVirtualScanCode,
                unicode_char,
                control_state: key.dwControlKeyState,
            });
        }
    }

    fn queue_event(&mut self, event: ConsoleKeyEvent) {
        let units = translate_key_event(event);
        for _ in 0..event.repeat_count {
            for unit in &units {
                match unit {
                    InputUnit::Bytes(bytes) => {
                        self.flush_pending_surrogate();
                        self.buffered.extend(bytes);
                    }
                    InputUnit::Utf16(unit) => self.queue_utf16_unit(*unit),
                }
            }
        }
    }

    fn queue_utf16_unit(&mut self, unit: u16) {
        if (0xd800..=0xdbff).contains(&unit) {
            if self.pending_high_surrogate.replace(unit).is_some() {
                self.buffered.extend(REPLACEMENT_CHARACTER);
            }
            return;
        }

        if (0xdc00..=0xdfff).contains(&unit) {
            if let Some(high) = self.pending_high_surrogate.take() {
                let code_point =
                    0x1_0000 + ((u32::from(high) - 0xd800) << 10) + (u32::from(unit) - 0xdc00);
                if let Some(ch) = char::from_u32(code_point) {
                    let mut encoded = [0_u8; 4];
                    self.buffered
                        .extend(ch.encode_utf8(&mut encoded).as_bytes());
                    return;
                }
            }
            self.buffered.extend(REPLACEMENT_CHARACTER);
            return;
        }

        self.flush_pending_surrogate();
        if let Some(ch) = char::from_u32(u32::from(unit)) {
            let mut encoded = [0_u8; 4];
            self.buffered
                .extend(ch.encode_utf8(&mut encoded).as_bytes());
        }
    }

    fn flush_pending_surrogate(&mut self) {
        if self.pending_high_surrogate.take().is_some() {
            self.buffered.extend(REPLACEMENT_CHARACTER);
        }
    }
}

impl Read for WindowsConsoleInput {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        while self.buffered.is_empty() {
            let event = self.read_key_event()?;
            self.queue_event(event);
        }

        let count = output.len().min(self.buffered.len());
        for byte in output.iter_mut().take(count) {
            *byte = self.buffered.pop_front().expect("长度已经检查");
        }
        Ok(count)
    }
}

fn translate_key_event(event: ConsoleKeyEvent) -> Vec<InputUnit> {
    let control_state = normalize_altgr(event.control_state, event.unicode_char);
    let enhanced = control_state & ENHANCED_KEY != 0;

    if enhanced {
        return match event.virtual_key {
            VK_RETURN => bytes(if is_ctrl(control_state) { b"\n" } else { b"\r" }),
            VK_PRIOR => modifier_bytes(b"\x1b[5~", event.virtual_key, control_state),
            VK_NEXT => modifier_bytes(b"\x1b[6~", event.virtual_key, control_state),
            VK_END => bytes(b"\x1b[F"),
            VK_HOME => bytes(b"\x1b[H"),
            VK_LEFT => modifier_bytes(b"\x1b[D", event.virtual_key, control_state),
            VK_UP => modifier_bytes(b"\x1b[A", event.virtual_key, control_state),
            VK_RIGHT => modifier_bytes(b"\x1b[C", event.virtual_key, control_state),
            VK_DOWN => modifier_bytes(b"\x1b[B", event.virtual_key, control_state),
            VK_INSERT => modifier_bytes(b"\x1b[2~", event.virtual_key, control_state),
            VK_DELETE => modifier_bytes(b"\x1b[3~", event.virtual_key, control_state),
            VK_DIVIDE => bytes(b"/"),
            _ => fallback_character(event.unicode_char),
        };
    }

    match event.virtual_key {
        VK_BACK => {
            if is_alt(control_state) {
                bytes(b"\x1b\x7f")
            } else {
                bytes(b"\x7f")
            }
        }
        VK_TAB => {
            if is_shift(control_state) {
                bytes(b"\x1b[Z")
            } else {
                bytes(b"\t")
            }
        }
        VK_CLEAR => keypad_bytes(b"\x1b[E", b'5', event.virtual_key, control_state, false),
        VK_RETURN => {
            if is_alt(control_state) {
                bytes(b"\x1b\n")
            } else if is_ctrl(control_state) {
                bytes(b"\n")
            } else {
                bytes(b"\r")
            }
        }
        VK_SPACE => {
            if is_alt(control_state) {
                bytes(b"\x1b ")
            } else if is_ctrl(control_state) {
                bytes(&[0])
            } else {
                bytes(b" ")
            }
        }
        VK_PRIOR => modifier_keypad_bytes(b"\x1b[5~", b'9', event.virtual_key, control_state),
        VK_NEXT => modifier_keypad_bytes(b"\x1b[6~", b'3', event.virtual_key, control_state),
        VK_END => keypad_bytes(b"\x1b[4~", b'1', event.virtual_key, control_state, false),
        VK_HOME => keypad_bytes(b"\x1b[1~", b'7', event.virtual_key, control_state, false),
        VK_LEFT => modifier_keypad_bytes(b"\x1b[D", b'4', event.virtual_key, control_state),
        VK_UP => modifier_keypad_bytes(b"\x1b[A", b'8', event.virtual_key, control_state),
        VK_RIGHT => modifier_keypad_bytes(b"\x1b[C", b'6', event.virtual_key, control_state),
        VK_DOWN => modifier_keypad_bytes(b"\x1b[B", b'2', event.virtual_key, control_state),
        VK_INSERT => modifier_keypad_bytes(b"\x1b[2~", b'0', event.virtual_key, control_state),
        VK_DELETE => {
            let decimal = unsafe { MapVirtualKeyW(u32::from(VK_DECIMAL), MAPVK_VK_TO_CHAR) } as u8;
            modifier_keypad_bytes(b"\x1b[3~", decimal, event.virtual_key, control_state)
        }
        VK_NUMPAD0..=VK_NUMPAD9 => bytes(&[b'0' + (event.virtual_key - VK_NUMPAD0) as u8]),
        VK_MULTIPLY => bytes(b"*"),
        windows_sys::Win32::UI::Input::KeyboardAndMouse::VK_ADD => bytes(b"+"),
        VK_SUBTRACT => bytes(b"-"),
        VK_DECIMAL => character_without_modifier(event, control_state, Modifier::Control),
        VK_F1 => modifier_bytes(b"\x1bOP", event.virtual_key, control_state),
        VK_F2 => modifier_bytes(b"\x1bOQ", event.virtual_key, control_state),
        VK_F3 => modifier_bytes(b"\x1bOR", event.virtual_key, control_state),
        VK_F4 => modifier_bytes(b"\x1bOS", event.virtual_key, control_state),
        VK_F5 => modifier_bytes(b"\x1b[15~", event.virtual_key, control_state),
        VK_F6 => modifier_bytes(b"\x1b[17~", event.virtual_key, control_state),
        VK_F7 => modifier_bytes(b"\x1b[18~", event.virtual_key, control_state),
        VK_F8 => modifier_bytes(b"\x1b[19~", event.virtual_key, control_state),
        VK_F9 => modifier_bytes(b"\x1b[20~", event.virtual_key, control_state),
        VK_F10 => modifier_bytes(b"\x1b[21~", event.virtual_key, control_state),
        VK_F11 => modifier_bytes(b"\x1b[23~", event.virtual_key, control_state),
        VK_F12 => modifier_bytes(b"\x1b[24~", event.virtual_key, control_state),
        VK_F13 => modifier_bytes(b"\x1b[25~", event.virtual_key, control_state),
        VK_F14 => modifier_bytes(b"\x1b[26~", event.virtual_key, control_state),
        VK_F15 => modifier_bytes(b"\x1b[28~", event.virtual_key, control_state),
        VK_F16 => modifier_bytes(b"\x1b[29~", event.virtual_key, control_state),
        VK_F17 => modifier_bytes(b"\x1b[31~", event.virtual_key, control_state),
        VK_F18 => modifier_bytes(b"\x1b[32~", event.virtual_key, control_state),
        VK_F19 => modifier_bytes(b"\x1b[33~", event.virtual_key, control_state),
        VK_F20 => modifier_bytes(b"\x1b[34~", event.virtual_key, control_state),
        0x41..=0x5a => {
            let mut units = character_without_modifier(event, control_state, Modifier::Alt);
            if is_alt(control_state) {
                prefix_escape(&mut units);
            }
            units
        }
        virtual_key if is_control_punctuation(virtual_key) => {
            let unit = character_unit_without_modifier(event, control_state, Modifier::Control);
            let mut units = control_character(unit, control_state);
            if should_prefix_control_alt(virtual_key, control_state) {
                prefix_escape(&mut units);
            }
            units
        }
        _ => fallback_character(event.unicode_char),
    }
}

fn bytes(value: &[u8]) -> Vec<InputUnit> {
    vec![InputUnit::Bytes(value.to_vec())]
}

fn fallback_character(unit: u16) -> Vec<InputUnit> {
    if unit == 0 {
        Vec::new()
    } else {
        vec![InputUnit::Utf16(unit)]
    }
}

fn modifier_bytes(normal: &[u8], virtual_key: u16, state: u32) -> Vec<InputUnit> {
    bytes(&modifier_sequence(
        normal,
        normalize_keypad_state(virtual_key, state),
    ))
}

fn modifier_sequence(normal: &[u8], state: u32) -> Vec<u8> {
    let mut code = 0_u8;
    if is_shift(state) {
        code |= 1;
    }
    if is_alt(state) {
        code |= 2;
    }
    if is_ctrl(state) {
        code |= 4;
    }
    if code == 0 || normal.is_empty() {
        return normal.to_vec();
    }

    let mut sequence = normal[..normal.len() - 1].to_vec();
    let last = normal[normal.len() - 1];
    if last != b'~' {
        sequence.push(b'1');
    }
    sequence.extend_from_slice(&[b';', b'1' + code, last]);
    sequence
}

fn keypad_bytes(
    normal: &[u8],
    shifted: u8,
    virtual_key: u16,
    state: u32,
    modifiers: bool,
) -> Vec<InputUnit> {
    if is_shift(state) {
        bytes(&[shifted])
    } else if modifiers {
        bytes(&modifier_sequence(
            normal,
            normalize_keypad_state(virtual_key, state),
        ))
    } else {
        bytes(normal)
    }
}

fn modifier_keypad_bytes(
    normal: &[u8],
    shifted: u8,
    virtual_key: u16,
    state: u32,
) -> Vec<InputUnit> {
    keypad_bytes(normal, shifted, virtual_key, state, true)
}

#[derive(Clone, Copy)]
enum Modifier {
    Control,
    Alt,
}

fn character_without_modifier(
    event: ConsoleKeyEvent,
    state: u32,
    modifier: Modifier,
) -> Vec<InputUnit> {
    let unit = character_unit_without_modifier(event, state, modifier);
    fallback_character(unit)
}

fn character_unit_without_modifier(event: ConsoleKeyEvent, state: u32, modifier: Modifier) -> u16 {
    if event.unicode_char != 0 {
        return event.unicode_char;
    }

    let modifier_pressed = match modifier {
        Modifier::Control => is_ctrl(state),
        Modifier::Alt => is_alt(state),
    };
    if !modifier_pressed {
        return 0;
    }

    let mut keyboard_state = [0_u8; 256];
    keyboard_state[0x10] = if is_shift(state) { 0x80 } else { 0 };
    keyboard_state[0x11] = if is_ctrl(state) { 0x80 } else { 0 };
    keyboard_state[0x12] = if is_alt(state) { 0x80 } else { 0 };
    keyboard_state[0x14] = if state & CAPSLOCK_ON != 0 { 1 } else { 0 };
    match modifier {
        Modifier::Control => keyboard_state[0x11] = 0,
        Modifier::Alt => keyboard_state[0x12] = 0,
    }

    let mut translated = [0_u16; 4];
    let count = unsafe {
        ToUnicode(
            u32::from(event.virtual_key),
            u32::from(event.scan_code),
            keyboard_state.as_ptr(),
            translated.as_mut_ptr(),
            translated.len() as i32,
            0,
        )
    };
    if count == 1 { translated[0] } else { 0 }
}

fn control_character(unit: u16, state: u32) -> Vec<InputUnit> {
    let Some(mut ch) = u8::try_from(unit).ok() else {
        return fallback_character(unit);
    };
    if is_ctrl(state) {
        ch = match ch {
            b'2' | b'@' | b'`' => 0,
            b'3' | b'[' | b'{' => 0x1b,
            b'4' | b'\\' | b'|' => 0x1c,
            b'5' | b']' | b'}' => 0x1d,
            b'6' | b'^' | b'~' => 0x1e,
            b'7' | b'-' | b'_' => 0x1f,
            b'8' => 0x7f,
            b'/' if !is_alt(state) => 0x1f,
            b'?' if !is_alt(state) => 0x7f,
            _ => ch,
        };
    }
    bytes(&[ch])
}

fn prefix_escape(units: &mut Vec<InputUnit>) {
    if !units.is_empty() {
        units.insert(0, InputUnit::Bytes(vec![ESC]));
    }
}

fn normalize_altgr(mut state: u32, unicode_char: u16) -> u32 {
    if unicode_char == 0 || !is_ctrl(state) || !is_alt(state) {
        return state;
    }
    if state & RIGHT_ALT_PRESSED != 0 {
        state &= !(RIGHT_ALT_PRESSED | LEFT_CTRL_PRESSED);
    } else if state & LEFT_ALT_PRESSED != 0 {
        state &= !LEFT_ALT_PRESSED;
        if state & LEFT_CTRL_PRESSED != 0 {
            state &= !LEFT_CTRL_PRESSED;
        } else {
            state &= !RIGHT_CTRL_PRESSED;
        }
    }
    state
}

fn normalize_keypad_state(virtual_key: u16, state: u32) -> u32 {
    if state & NUMLOCK_ON == 0 || state & ENHANCED_KEY != 0 {
        return state;
    }
    if matches!(
        virtual_key,
        VK_INSERT
            | VK_DELETE
            | VK_END
            | VK_DOWN
            | VK_NEXT
            | VK_LEFT
            | VK_CLEAR
            | VK_RIGHT
            | VK_HOME
            | VK_UP
            | VK_PRIOR
    ) {
        state | SHIFT_PRESSED
    } else {
        state
    }
}

fn is_control_punctuation(virtual_key: u16) -> bool {
    matches!(
        virtual_key,
        0x30..=0x39
            | VK_OEM_1
            | VK_OEM_PLUS
            | VK_OEM_COMMA
            | VK_OEM_PERIOD
            | VK_OEM_7
            | VK_OEM_102
            | VK_OEM_2
            | VK_OEM_3
            | VK_OEM_4
            | VK_OEM_5
            | VK_OEM_6
            | VK_OEM_MINUS
    )
}

fn is_ctrl_alt_shift_exception(virtual_key: u16) -> bool {
    matches!(virtual_key, 0x32..=0x38 | VK_OEM_MINUS)
}

fn should_prefix_control_alt(virtual_key: u16, state: u32) -> bool {
    is_alt(state)
        && (!is_ctrl_alt_shift_exception(virtual_key) || !is_ctrl(state) || is_shift(state))
}

fn is_shift(state: u32) -> bool {
    state & SHIFT_PRESSED != 0
}

fn is_ctrl(state: u32) -> bool {
    state & (LEFT_CTRL_PRESSED | RIGHT_CTRL_PRESSED) != 0
}

fn is_alt(state: u32) -> bool {
    state & (LEFT_ALT_PRESSED | RIGHT_ALT_PRESSED) != 0
}

fn should_accept_key_record(key_down: bool, repeat_count: u16, unicode_char: u16) -> bool {
    repeat_count != 0 && (key_down || (0xd800..=0xdfff).contains(&unicode_char))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(virtual_key: u16, unicode_char: u16, control_state: u32) -> ConsoleKeyEvent {
        ConsoleKeyEvent {
            repeat_count: 1,
            virtual_key,
            scan_code: 0,
            unicode_char,
            control_state,
        }
    }

    fn translate(event: ConsoleKeyEvent) -> Vec<u8> {
        let mut input = WindowsConsoleInput {
            handle: std::ptr::null_mut(),
            buffered: VecDeque::new(),
            pending_high_surrogate: None,
        };
        input.queue_event(event);
        input.buffered.into_iter().collect()
    }

    #[test]
    fn enhanced_arrows_and_function_keys_match_aosp_sequences() {
        assert_eq!(translate(event(VK_UP, 0, ENHANCED_KEY)), b"\x1b[A");
        assert_eq!(
            translate(event(
                VK_UP,
                0,
                ENHANCED_KEY | SHIFT_PRESSED | LEFT_CTRL_PRESSED
            )),
            b"\x1b[1;6A"
        );
        assert_eq!(translate(event(VK_F5, 0, LEFT_ALT_PRESSED)), b"\x1b[15;3~");
    }

    #[test]
    fn editing_keys_and_control_bytes_match_aosp_sequences() {
        assert_eq!(translate(event(VK_BACK, 0, 0)), b"\x7f");
        assert_eq!(translate(event(VK_BACK, 0, LEFT_ALT_PRESSED)), b"\x1b\x7f");
        assert_eq!(translate(event(VK_TAB, 0, SHIFT_PRESSED)), b"\x1b[Z");
        assert_eq!(translate(event(0x43, 3, LEFT_CTRL_PRESSED)), &[3]);
        assert_eq!(translate(event(VK_SPACE, 0, LEFT_CTRL_PRESSED)), &[0]);
        assert_eq!(translate(event(VK_RETURN, 0, LEFT_CTRL_PRESSED)), b"\n");
        assert_eq!(
            translate(event(0x32, b'2'.into(), LEFT_ALT_PRESSED)),
            b"\x1b2"
        );
        assert!(!should_prefix_control_alt(
            0x32,
            LEFT_ALT_PRESSED | LEFT_CTRL_PRESSED
        ));
        assert!(should_prefix_control_alt(
            0x32,
            LEFT_ALT_PRESSED | LEFT_CTRL_PRESSED | SHIFT_PRESSED
        ));
    }

    #[test]
    fn keypad_shift_and_numlock_order_matches_aosp() {
        assert_eq!(translate(event(VK_LEFT, 0, 0)), b"\x1b[D");
        assert_eq!(translate(event(VK_LEFT, 0, SHIFT_PRESSED)), b"4");
        assert_eq!(
            translate(event(VK_LEFT, 0, LEFT_CTRL_PRESSED)),
            b"\x1b[1;5D"
        );
        assert_eq!(translate(event(VK_LEFT, 0, NUMLOCK_ON)), b"\x1b[1;2D");
    }

    #[test]
    fn altgr_character_does_not_get_escape_prefix() {
        assert_eq!(
            translate(event(
                VK_OEM_6,
                ']' as u16,
                RIGHT_ALT_PRESSED | LEFT_CTRL_PRESSED
            )),
            b"]"
        );
    }

    #[test]
    fn unicode_and_surrogate_pairs_are_encoded_as_utf8() {
        assert_eq!(translate(event(0, '\u{4e2d}' as u16, 0)), "中".as_bytes());

        let mut input = WindowsConsoleInput {
            handle: std::ptr::null_mut(),
            buffered: VecDeque::new(),
            pending_high_surrogate: None,
        };
        input.queue_event(event(0, 0xd83d, 0));
        assert!(input.buffered.is_empty());
        input.queue_event(event(0, 0xde00, 0));
        assert_eq!(
            input.buffered.into_iter().collect::<Vec<_>>(),
            "😀".as_bytes()
        );

        assert!(!should_accept_key_record(false, 1, 'a' as u16));
        assert!(should_accept_key_record(false, 1, 0xd83d));
        assert!(should_accept_key_record(false, 1, 0xde00));
    }

    #[test]
    fn repeat_count_repeats_the_complete_sequence() {
        let mut repeated = event(VK_UP, 0, ENHANCED_KEY);
        repeated.repeat_count = 2;
        assert_eq!(translate(repeated), b"\x1b[A\x1b[A");
    }

    #[test]
    fn control_punctuation_mapping_matches_aosp() {
        assert_eq!(
            flatten(control_character(b'2'.into(), LEFT_CTRL_PRESSED)),
            &[0]
        );
        assert_eq!(
            flatten(control_character(b'['.into(), LEFT_CTRL_PRESSED)),
            &[ESC]
        );
        assert_eq!(
            flatten(control_character(b'?'.into(), LEFT_CTRL_PRESSED)),
            &[0x7f]
        );
    }

    fn flatten(units: Vec<InputUnit>) -> Vec<u8> {
        units
            .into_iter()
            .flat_map(|unit| match unit {
                InputUnit::Bytes(bytes) => bytes,
                InputUnit::Utf16(unit) => char::from_u32(u32::from(unit))
                    .unwrap()
                    .to_string()
                    .into_bytes(),
            })
            .collect()
    }
}
