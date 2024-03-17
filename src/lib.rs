use std::fmt::Display;
use std::fs;
use std::mem::{self, size_of};
use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use winapi::um::winnt::ULARGE_INTEGER;
use windows::core::HSTRING;
use windows::Win32::Foundation::{CloseHandle, FILETIME};
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, MODULEENTRY32W, TH32CS_SNAPALL, TH32CS_SNAPMODULE,
    TH32CS_SNAPMODULE32,
};
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows::Win32::System::Memory::{VirtualAllocEx, MEM_COMMIT, PAGE_EXECUTE_READ};
use windows::Win32::System::ProcessStatus::GetProcessMemoryInfo;
use windows::Win32::System::Threading::{
    CreateRemoteThread, GetPriorityClass, GetProcessTimes, OpenProcess, SetPriorityClass, TerminateProcess, LPTHREAD_START_ROUTINE, PROCESS_ALL_ACCESS, PROCESS_CREATION_FLAGS
};
use windows::{
    core::{PCSTR, PCWSTR},
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
    pub module: MODULEENTRY32W,

    ///Im not sure if this works 100% of the time XD
    pub processor_usage: f64,
}

impl ProcessAttributes {
    pub fn new(
        process_memory: PROCESS_MEMORY_COUNTERS,
        process_cpu_info: CpuTime,
        process: PROCESSENTRY32W,
        module: MODULEENTRY32W,
    ) -> Self {
        Self {
            process_memory,
            process_cpu_info,
            process,
            module,

            processor_usage: 0.,
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

fn create_snapshot_from_all() -> Result<HANDLE, windows::core::Error> {
    unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0) }
}

fn create_module_snapshot_from_pid(pid: u32) -> Result<HANDLE, windows::core::Error> {
    unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid) }
}

fn get_module_from_snapshot(hsnapshot: HANDLE) -> anyhow::Result<MODULEENTRY32W> {
    let mut me32 = MODULEENTRY32W {
        dwSize: size_of::<MODULEENTRY32W>() as u32,
        ..Default::default()
    };

    unsafe {
        Module32FirstW(hsnapshot, &mut me32)?;
    }

    Ok(me32)
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
        let mut me32 = MODULEENTRY32W::default();

        while Process32NextW(hsnapshot, &mut pe32).is_ok() {
            let process_id = pe32.th32ProcessID;

            match OpenProcess(PROCESS_ALL_ACCESS, false, process_id) {
                Ok(process_handle) => {
                    let process_memory = get_memory_usage(process_handle)?;
                    let process_cpu_times = get_cpu_times(process_handle)?;

                    me32 = get_module_from_snapshot(create_module_snapshot_from_pid(process_id)?)?;

                    proc_attr_list.push(ProcessAttributes::new(
                        process_memory,
                        process_cpu_times,
                        pe32,
                        me32,
                    ));
                }
                Err(err) => {
                    // dbg!(err);
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
    let snapshot = create_snapshot_from_all()?;
    let proc_list = get_proc_attr_list(snapshot);

    //Close handle
    unsafe {
        CloseHandle(snapshot)?;
    }

    proc_list
}

pub fn fetch_raw_string(proc_name_raw: [u16; 260]) -> String {
    String::from_utf8(
        proc_name_raw
            .to_vec()
            .iter()
            .map(|num| *num as u8)
            .collect::<Vec<u8>>(),
    )
    .unwrap()
}

pub fn fetch_proc_path(proc_path_raw: [u16; 260]) -> PathBuf {
    //We can use the fetch_raw_string fn to turn the path into a string then to a pathbuf
    PathBuf::from_str(&fetch_raw_string(proc_path_raw)).unwrap()
}

pub fn terminate_process(pid: u32) -> anyhow::Result<()> {
    unsafe {
        let process_handle = OpenProcess(PROCESS_ALL_ACCESS, false, pid)?;

        TerminateProcess(process_handle, 0)?;

        CloseHandle(process_handle)?;
    }

    Ok(())
}

pub fn set_priority_class_process(
    pid: u32,
    priority: PROCESS_CREATION_FLAGS,
) -> anyhow::Result<()> {
    unsafe {
        let process_handle = OpenProcess(PROCESS_ALL_ACCESS, false, pid)?;

        SetPriorityClass(process_handle, priority)?;

        CloseHandle(process_handle)?;
    }

    Ok(())
}

pub fn get_priority_class_process(pid: u32) -> anyhow::Result<PROCESS_CREATION_FLAGS> {
    unsafe {
        let process_handle = OpenProcess(PROCESS_ALL_ACCESS, false, pid)?;

        let priority = GetPriorityClass(process_handle);

        CloseHandle(process_handle)?;

        Ok(PROCESS_CREATION_FLAGS(priority))
    }
}

pub fn inject_dll_into_process(pid: u32, path_to_dll: PathBuf) -> anyhow::Result<()> {
    let dll = fs::read(&path_to_dll)?;
    dbg!(&path_to_dll);
    unsafe {
        let process_handle = OpenProcess(PROCESS_ALL_ACCESS, false, pid)?;

        let allocated_address = VirtualAllocEx(
            process_handle,
            None,
            dll.len(),
            MEM_COMMIT,
            PAGE_EXECUTE_READ,
        );

        // WriteProcessMemory(process_handle, allocated_address, lpbuffer, nsize, None);

        let lib_name = path_to_dll.as_os_str().encode_wide().collect::<Vec<_>>();

        let hstring = HSTRING::from_wide(&lib_name)?;

        let pcwstr = PCWSTR::from_raw(hstring.as_ptr());

        //Load module
        //Module not found
        let lib = LoadLibraryW(pcwstr)?;

        //Write process memory
        WriteProcessMemory(
            process_handle,
            allocated_address,
            dll.as_ptr() as *const _,
            dll.len(),
            None,
        )?;
        
        // let proc_address = GetProcAddress(lib, PCSTR::from_raw("LoadLibraryW\0".as_ptr()));

        //LPTHREAD_START_ROUTINE -> ENTRY ADDRESS FOR THE NEW THREAD
        //https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread
        let remote_thread = CreateRemoteThread(
            process_handle,
            None,
            0,
            Some(std::mem::transmute(allocated_address)),
            Some(allocated_address),
            0,
            None,
        )?;

        // let _: LPTHREAD_START_ROUTINE = std::mem::transmute(allocated_address);

        CloseHandle(process_handle)?;
    }

    Ok(())
}
