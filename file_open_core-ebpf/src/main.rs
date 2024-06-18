#![no_std]
#![no_main]

#[allow(non_camel_case_types)]
#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(dead_code)]
mod vmlinux;

mod access;

use core::ffi::c_char;
use aya_ebpf::{
    macros::lsm,
    programs::LsmContext,
};
use aya_log_ebpf::info;
use aya_ebpf::cty::{c_ulong};


#[lsm(hook = "file_open")]
pub fn file_open(ctx: LsmContext) -> i32 {
    unsafe {
        try_file_open(ctx).unwrap_or(0)
    }
}

unsafe fn try_file_open(ctx: LsmContext) -> Result<i32, i64> {
    let task_file = get_file_for_current_task().map_err(|_| 0)?;
    if task_file.is_null() {
        return Ok(0);
    }
    let mut buf = [0u8; 128];
    read_path(task_file, buf.as_mut_slice())?;
    let root = buf[0];
    info!(&ctx, "{}", root);

    Ok(0)
}

unsafe fn get_file_for_current_task() -> Result<*const vmlinux::file, i64> {
    let task = aya_ebpf::helpers::bpf_get_current_task() as *mut vmlinux::task_struct;
    let mm = aya_ebpf::helpers::bpf_probe_read_kernel(access::task_struct_mm(task))?;
    aya_ebpf::helpers::bpf_probe_read_kernel(access::mm_exe_file(mm))
}

/// Read the file's path into dst.
unsafe fn read_path(file: *const vmlinux::file, dst: &mut [u8]) -> Result<i32, i32> {
    let btf_path = access::file_f_path(file);
    if aya_ebpf::helpers::bpf_d_path(
        btf_path as *mut _,
        dst.as_mut_ptr() as *mut c_char,
        dst.len() as u32,
    ) < 0
    {
        // It's possible that the buffer did not have enough capacity.
        return Err(0);
    }
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
