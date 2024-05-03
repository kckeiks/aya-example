#![no_std]
#![no_main]

#[allow(non_camel_case_types)]
#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(dead_code)]
mod vmlinux;

mod access;

use aya_ebpf::{
    macros::lsm,
    programs::LsmContext,
};
use aya_log_ebpf::info;
use aya_ebpf::cty::{c_ulong};


#[lsm(hook = "file_open")]
pub fn file_open(ctx: LsmContext) -> i32 {
    match try_file_open(ctx) {
        Ok(ret) => ret,
        Err(ret) => 0i32,
    }
}

fn try_file_open(ctx: LsmContext) -> Result<i32, i64> {
    info!(&ctx, "lsm hook file_open called");
    unsafe {
        let ctx_file: *const vmlinux::file = ctx.arg(0);
        let inodee: *const vmlinux::inode = aya_ebpf::helpers::bpf_probe_read_kernel(access::file_inode(ctx_file))?;
        let inode_n: c_ulong = aya_ebpf::helpers::bpf_probe_read_kernel(access::inode_i_ino(inodee))?;
        info!(&ctx, "file_open attempt on {}", inode_n);
    }
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
