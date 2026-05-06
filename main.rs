#![windows_subsystem = "windows"]

use std::{
    collections::{HashMap, HashSet},
    fs,
    thread,
    time::{Duration, Instant},
};

use sysinfo::{
    ProcessRefreshKind,
    RefreshKind,
    System,
};

use windows::{
    Win32::{
        Foundation::{BOOL, HWND, LPARAM},
        UI::WindowsAndMessaging::{
            EnumWindows,
            GetWindowTextLengthW,
            GetWindowTextW,
            GetWindowThreadProcessId,
            IsWindowVisible,
        },
    },
};

fn load_watchlist(path: &str) -> HashSet<String> {
    fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .collect()
}

unsafe extern "system" fn enum_windows_proc(
    hwnd: HWND,
    lparam: LPARAM,
) -> BOOL {
    if !IsWindowVisible(hwnd).as_bool() {
        return BOOL(1);
    }

    let len = GetWindowTextLengthW(hwnd);

    if len == 0 {
        return BOOL(1);
    }

    let mut buffer = vec![0u16; (len + 1) as usize];

    GetWindowTextW(hwnd, &mut buffer);

    let mut pid = 0u32;

    GetWindowThreadProcessId(hwnd, Some(&mut pid));

    let pids = &mut *(lparam.0 as *mut HashSet<u32>);

    pids.insert(pid);

    BOOL(1)
}

fn get_visible_window_pids() -> HashSet<u32> {
    let mut pids = HashSet::new();

    unsafe {
        EnumWindows(
            Some(enum_windows_proc),
            LPARAM(&mut pids as *mut _ as isize),
        );
    }

    pids
}

fn main() {
    let watchlist = load_watchlist("watchlist.txt");

    let mut system = System::new_with_specifics(
        RefreshKind::new()
            .with_processes(ProcessRefreshKind::new()),
    );

    // lưu thời gian phát hiện process nền
    let mut hidden_since: HashMap<u32, Instant> = HashMap::new();

    loop {
        let visible_pids = get_visible_window_pids();

        system.refresh_processes_specifics(
            ProcessRefreshKind::new(),
        );

        for process in system.processes().values() {
            let name = process.name().to_lowercase();

            if !watchlist.contains(&name) {
                continue;
            }

            let pid = process.pid().as_u32();

            // đang mở cửa sổ
            if visible_pids.contains(&pid) {
                hidden_since.remove(&pid);
                continue;
            }

            // chưa có thì ghi thời gian
            hidden_since
                .entry(pid)
                .or_insert_with(Instant::now);

            // nếu nền > 20 giây mới kill
            if let Some(start) = hidden_since.get(&pid) {
                if start.elapsed() > Duration::from_secs(20) {
                    let _ = process.kill();
                    hidden_since.remove(&pid);
                }
            }
        }

        thread::sleep(Duration::from_secs(10));
    }
}