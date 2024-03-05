use std::fmt::Display;

use windows::Win32::Foundation::CloseHandle;
use windows::Win32::Security::{SE_DEBUG_NAME, TOKEN_WRITE_OWNER};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Toolhelp32ReadProcessMemory, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::ProcessStatus::GetProcessMemoryInfo;
use windows::Win32::System::Threading::{
    GetProcessWorkingSetSize, OpenProcess, PROCESS_ALL_ACCESS, PROCESS_READ_CONTROL,
    PROCESS_VM_OPERATION, SYNCHRONIZATION_READ_CONTROL,
};
use windows::{
    core::PCWSTR,
    Win32::{
        Foundation::{HANDLE, HWND},
        System::{
            Diagnostics::ToolHelp::{Process32FirstW, Process32NextW, PROCESSENTRY32W},
            ProcessStatus::PROCESS_MEMORY_COUNTERS,
            Threading::{
                GetCurrentProcess, GetCurrentProcessId, GetProcessId, QueryFullProcessImageNameW,
                PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
            },
        },
        UI::WindowsAndMessaging::{MessageBoxW, HWND_DESKTOP, MB_ICONERROR},
    },
};

pub fn get_self_proc_id() -> u32 {
    unsafe { GetProcessId(GetCurrentProcess()) }
}

fn alloc_proc_entry() -> PROCESSENTRY32W {
    PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    }
}

fn create_snapshot() -> Result<HANDLE, windows::core::Error> {
    unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }
}

fn get_proc_list(hsnapshot: HANDLE) -> anyhow::Result<Vec<PROCESSENTRY32W>> {
    let mut proc_list: Vec<PROCESSENTRY32W> = Vec::new();

    unsafe {
        let mut pe32 = alloc_proc_entry();

        Process32FirstW(hsnapshot, &mut pe32)?;
        while let Ok(_) = Process32NextW(hsnapshot, &mut pe32) {
            proc_list.push(pe32);
        }
    }

    Ok(proc_list)
}

pub fn get_memory_usage(pid: u32) -> anyhow::Result<usize> {
    unsafe {
        let process_handle = OpenProcess(PROCESS_ALL_ACCESS, true, pid)?;

        let mut pmc = PROCESS_MEMORY_COUNTERS::default();
        let cb = std::mem::size_of_val(&pmc) as u32;
        GetProcessMemoryInfo(process_handle, &mut pmc, cb)?;

        CloseHandle(process_handle)?;

        Ok(pmc.PagefileUsage)
    }
}

pub fn display_error_message(
    caption: impl Display + std::marker::Send + 'static,
    title: impl Display + std::marker::Send + 'static,
) {
    std::thread::spawn(move || unsafe {
        MessageBoxW(
            HWND_DESKTOP,
            PCWSTR::from_raw(
                str::encode_utf16(caption.to_string().as_str())
                    .chain(std::iter::once(0))
                    .collect::<Vec<_>>()
                    .as_ptr(),
            ),
            PCWSTR::from_raw(
                str::encode_utf16(title.to_string().as_str())
                    .chain(std::iter::once(0))
                    .collect::<Vec<_>>()
                    .as_ptr(),
            ),
            MB_ICONERROR,
        );
    });
}

pub fn get_process_list() -> anyhow::Result<Vec<PROCESSENTRY32W>> {
    let snapshot = create_snapshot()?;
    let proc_list = get_proc_list(snapshot);

    //Close handle
    unsafe {
        CloseHandle(snapshot)?;
    }

    proc_list
}

pub fn fetch_proc_name(proc_name_raw: [u16; 260]) -> String {
    String::from_utf8(
        proc_name_raw
            .to_vec()
            .iter()
            .map(|num| *num as u8)
            .collect::<Vec<u8>>(),
    )
    .unwrap()
}
