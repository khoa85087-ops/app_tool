#![windows_subsystem = "windows"]

use std::mem::{size_of, zeroed};

use winapi::shared::minwindef::*;
use winapi::shared::windef::*;
use winapi::um::libloaderapi::GetModuleHandleW;
use winapi::um::sysinfoapi::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
use winapi::um::processthreadsapi::GetSystemTimes;
use winapi::um::wingdi::*;
use winapi::um::winuser::*;

static mut CPU: f32 = 0.0;
static mut RAM: f32 = 0.0;

static mut LAST_IDLE: u64 = 0;
static mut LAST_TOTAL: u64 = 0;

const W: i32 = 120;
const H: i32 = 44;

const BG: COLORREF = 0x00202020;
const TXT: COLORREF = 0x00F2F2F2;

// ===== CPU =====
fn cpu_usage() -> f32 {
    unsafe {
        let mut i = zeroed();
        let mut k = zeroed();
        let mut u = zeroed();

        GetSystemTimes(&mut i, &mut k, &mut u);

        let i = ((i.dwHighDateTime as u64) << 32) | i.dwLowDateTime as u64;
        let k = ((k.dwHighDateTime as u64) << 32) | k.dwLowDateTime as u64;
        let u = ((u.dwHighDateTime as u64) << 32) | u.dwLowDateTime as u64;

        let total = k + u;

        if LAST_TOTAL == 0 {
            LAST_IDLE = i;
            LAST_TOTAL = total;
            return 0.0;
        }

        let di = i - LAST_IDLE;
        let dt = total - LAST_TOTAL;

        LAST_IDLE = i;
        LAST_TOTAL = total;

        if dt == 0 { 0.0 } else {
            ((dt - di) as f32 / dt as f32) * 100.0
        }
    }
}

// ===== RAM =====
fn ram_usage() -> f32 {
    unsafe {
        let mut m: MEMORYSTATUSEX = zeroed();
        m.dwLength = size_of::<MEMORYSTATUSEX>() as u32;
        GlobalMemoryStatusEx(&mut m);
        m.dwMemoryLoad as f32
    }
}

// ===== WINDOW =====
unsafe extern "system" fn proc(
    hwnd: HWND, msg: UINT, w: WPARAM, l: LPARAM
) -> LRESULT {
    match msg {

        WM_CREATE => {
            CPU = cpu_usage();
            RAM = ram_usage();
            0
        }

        WM_TIMER => {
            CPU = cpu_usage();
            RAM = ram_usage();

            // 🔥 FIX ẨN: luôn giữ topmost
            SetWindowPos(
                hwnd,
                HWND_TOPMOST,
                0, 0, 0, 0,
                SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE,
            );

            InvalidateRect(hwnd, std::ptr::null_mut(), FALSE);
            0
        }

        WM_PAINT => {
            let mut ps: PAINTSTRUCT = zeroed();
            let hdc = BeginPaint(hwnd, &mut ps);

            let b = CreateSolidBrush(BG);
            let mut rc: RECT = zeroed();
            GetClientRect(hwnd, &mut rc);
            FillRect(hdc, &rc, b);
            DeleteObject(b as _);

            let name: Vec<u16> = "Segoe UI\0".encode_utf16().collect();
            let f = CreateFontW(
                16, 0, 0, 0,
                FW_MEDIUM as i32,
                0, 0, 0,
                DEFAULT_CHARSET as u32,
                OUT_TT_ONLY_PRECIS as u32,
                CLIP_DEFAULT_PRECIS as u32,
                CLEARTYPE_QUALITY as u32,
                DEFAULT_PITCH | FF_DONTCARE,
                name.as_ptr(),
            );

            let old = SelectObject(hdc, f as _);
            SetBkMode(hdc, TRANSPARENT as i32);
            SetTextColor(hdc, TXT);

            let s1 = format!("CPU {}%", CPU as i32);
            let s2 = format!("RAM {}%", RAM as i32);

            let w1: Vec<u16> = s1.encode_utf16().collect();
            let w2: Vec<u16> = s2.encode_utf16().collect();

            TextOutW(hdc, 10, 6, w1.as_ptr(), w1.len() as i32);
            TextOutW(hdc, 10, 24, w2.as_ptr(), w2.len() as i32);

            SelectObject(hdc, old);
            DeleteObject(f as _);

            EndPaint(hwnd, &ps);
            0
        }

        WM_LBUTTONDOWN => {
            ReleaseCapture();
            SendMessageW(hwnd, WM_NCLBUTTONDOWN, HTCAPTION as WPARAM, 0);
            0
        }

        WM_RBUTTONUP | WM_DESTROY => {
            PostQuitMessage(0);
            0
        }

        _ => DefWindowProcW(hwnd, msg, w, l)
    }
}

// ===== MAIN =====
fn main() {
    unsafe {
        let cls: Vec<u16> = "Overlay\0".encode_utf16().collect();
        let title: Vec<u16> = "overlay\0".encode_utf16().collect();

        let h = GetModuleHandleW(std::ptr::null_mut());

        let wc = WNDCLASSEXW {
            cbSize: size_of::<WNDCLASSEXW>() as u32,
            lpfnWndProc: Some(proc),
            hInstance: h,
            hCursor: LoadCursorW(std::ptr::null_mut(), IDC_ARROW),
            lpszClassName: cls.as_ptr(),
            ..zeroed()
        };

        RegisterClassExW(&wc);

        let sh = GetSystemMetrics(SM_CYSCREEN);

        let hwnd = CreateWindowExW(
            WS_EX_TOPMOST | WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW,
            cls.as_ptr(),
            title.as_ptr(),
            WS_POPUP,
            10,
            sh - H,
            W, H,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            h,
            std::ptr::null_mut(),
        );

        // 🔥 đảm bảo nổi ngay từ đầu
        SetWindowPos(
            hwnd,
            HWND_TOPMOST,
            0, 0, 0, 0,
            SWP_NOMOVE | SWP_NOSIZE,
        );

        ShowWindow(hwnd, SW_SHOWNOACTIVATE);
        UpdateWindow(hwnd);

        SetTimer(hwnd, 1, 1000, None);

        let mut msg: MSG = zeroed();
        while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
}