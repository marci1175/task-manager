use std::fmt::Display;
use std::mem;
use std::time::Duration;

use winapi::um::winnt::ULARGE_INTEGER;
use windows::Win32::Foundation::{CloseHandle, FILETIME, SYSTEMTIME};
use windows::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, TH32CS_SNAPPROCESS};
use windows::Win32::System::ProcessStatus::GetProcessMemoryInfo;
use windows::Win32::System::Threading::{GetProcessTimes, OpenProcess, TerminateProcess, PROCESS_ALL_ACCESS};
use windows::Win32::System::Time::FileTimeToSystemTime;
use windows::{
    core::PCWSTR,
    Win32::{
        Foundation::HANDLE,
        System::{
            Diagnostics::ToolHelp::{Process32NextW, PROCESSENTRY32W},
            ProcessStatus::PROCESS_MEMORY_COUNTERS,
            Threading::{GetCurrentProcess, GetProcessId},
        },
        UI::WindowsAndMessaging::{MessageBoxW, HWND_DESKTOP, MB_ICONERROR},
    },
};

#[derive(Debug, Clone)]
pub struct ProcessAttributes {
    pub process_memory: PROCESS_MEMORY_COUNTERS,
    pub process_cpu_info: CpuTime,
    pub process: PROCESSENTRY32W,
}

impl ProcessAttributes {
    pub fn new(
        process_memory: PROCESS_MEMORY_COUNTERS,
        process_cpu_info: CpuTime,
        process: PROCESSENTRY32W,
    ) -> Self {
        Self {
            process_memory,
            process_cpu_info,
            process,
        }
    }
}

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

#[derive(Debug, Clone)]
pub struct CpuTime {
    pub cpu_time_user: Duration,
    pub cpu_time_kernel: Duration,
}

fn filetime_to_u64(f: &FILETIME) -> u64 {
    unsafe {
        let mut v: ULARGE_INTEGER = mem::zeroed();
        v.s_mut().LowPart = f.dwLowDateTime;
        v.s_mut().HighPart = f.dwHighDateTime;
        *v.QuadPart()
    }
}

fn filetime_to_duration(f: &FILETIME) -> Duration {
    let hundred_nanos = filetime_to_u64(f);

    // 1 second is 10^9 nanoseconds,
    // so 1 second is 10^7 * (100 nanoseconds).
    let seconds = hundred_nanos / u64::pow(10, 7);
    // 1 second is 10^9 nanos which always fits in a u32.
    let nanos = ((hundred_nanos % u64::pow(10, 7)) * 100) as u32;

    Duration::new(seconds, nanos)
}

fn get_proc_attr_list(hsnapshot: HANDLE) -> anyhow::Result<Vec<ProcessAttributes>> {
    let mut proc_attr_list: Vec<ProcessAttributes> = Vec::new();

    unsafe {
        let mut pe32 = alloc_proc_entry();

        while let Ok(_) = Process32NextW(hsnapshot, &mut pe32) {
            let process_id = pe32.th32ProcessID;

            match OpenProcess(PROCESS_ALL_ACCESS, false, process_id) {
                Ok(process_handle) => {
                    let process_memory = get_memory_usage(process_handle)?;
                    let process_cpu_times = get_cpu_times(process_handle)?;

                    proc_attr_list.push(ProcessAttributes::new(
                        process_memory,
                        process_cpu_times,
                        pe32,
                    ));
                }
                Err(err) => {
                    dbg!(err);
                }
            };
        }
    }

    Ok(proc_attr_list)
}

fn get_memory_usage(process_handle: HANDLE) -> anyhow::Result<PROCESS_MEMORY_COUNTERS> {
    let mut pmc = PROCESS_MEMORY_COUNTERS::default();
    let cb = std::mem::size_of_val(&pmc) as u32;

    unsafe {
        GetProcessMemoryInfo(process_handle, &mut pmc, cb)?;
    }

    Ok(pmc)
}

fn get_cpu_times(process_handle: HANDLE) -> anyhow::Result<CpuTime> {
    let mut lp_creation_time = FILETIME::default();
    let mut lp_exit_time = FILETIME::default();
    let mut lp_kernel_time = FILETIME::default();
    let mut lp_user_time = FILETIME::default();

    unsafe {
        //here is where the error appears
        GetProcessTimes(
            process_handle,
            &mut lp_creation_time,
            &mut lp_exit_time,
            &mut lp_kernel_time,
            &mut lp_user_time,
        )?;
    }

    Ok(CpuTime {
        cpu_time_kernel: filetime_to_duration(&lp_kernel_time),
        cpu_time_user: filetime_to_duration(&lp_user_time),
    })
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

pub fn get_process_list() -> anyhow::Result<Vec<ProcessAttributes>> {
    let snapshot = create_snapshot()?;
    let proc_list = get_proc_attr_list(snapshot);

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

pub fn filetime_to_systemtime(mut file_time: FILETIME) -> anyhow::Result<SYSTEMTIME> {
    let mut systemtime = SYSTEMTIME::default();

    unsafe {
        FileTimeToSystemTime(&mut file_time, &mut systemtime)?;
    }

    Ok(systemtime)
}

pub fn terminate_process(pid: u32) -> anyhow::Result<()> {
    unsafe {
        let process_handle = OpenProcess(PROCESS_ALL_ACCESS, false, pid)?;

        TerminateProcess(process_handle, 0)?;
    
        CloseHandle(process_handle)?;
    }

    Ok(())
}