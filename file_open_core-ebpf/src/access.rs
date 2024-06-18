#![allow(unused)]
use aya_ebpf::cty::{c_int, c_uint, c_ulong, c_ushort};

use crate::vmlinux::{file, inode, mm_struct, path, task_struct};

extern "C" {
    pub fn file_inode(target: *const file) -> *const *const inode;
    pub fn inode_i_ino(target: *const inode) -> *const c_ulong;
    pub fn task_struct_mm(target: *const task_struct) -> *const *const mm_struct;
    pub fn mm_exe_file(target: *const mm_struct) -> *const *const file;
    pub fn file_f_path(target: *const file) -> *const path;

}
