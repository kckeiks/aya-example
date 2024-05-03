#![allow(unused)]
use aya_ebpf::cty::{c_int, c_uint, c_ulong, c_ushort};

use crate::vmlinux::{__kernel_ulong_t, cred, dentry, file, inode, linux_binprm, mm_struct, path, sockaddr, sockaddr_in, super_block, task_struct};

extern "C" {
    pub fn file_inode(target: *const file) -> *const *const inode;
    pub fn inode_i_ino(target: *const inode) -> *const c_ulong;
}
