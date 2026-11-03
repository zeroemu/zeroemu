//! Minimal FFI bindings to Apple's Hypervisor.framework (arm64).

#![allow(non_camel_case_types, dead_code)]

use std::ffi::c_void;

pub type hv_return_t = i32;
pub type hv_vcpu_t = u64;

pub const HV_SUCCESS: hv_return_t = 0;

pub const HV_MEMORY_READ: u64 = 1 << 0;
pub const HV_MEMORY_WRITE: u64 = 1 << 1;
pub const HV_MEMORY_EXEC: u64 = 1 << 2;

pub const HV_EXIT_REASON_CANCELED: u32 = 0;
pub const HV_EXIT_REASON_EXCEPTION: u32 = 1;
pub const HV_EXIT_REASON_VTIMER_ACTIVATED: u32 = 2;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct hv_vcpu_exit_exception_t {
    pub syndrome: u64,
    pub virtual_address: u64,
    pub physical_address: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct hv_vcpu_exit_t {
    pub reason: u32,
    pub exception: hv_vcpu_exit_exception_t,
}

// General purpose registers (hv_reg_t).
pub const HV_REG_X0: u32 = 0;
pub const HV_REG_PC: u32 = 31;
pub const HV_REG_FPCR: u32 = 32;
pub const HV_REG_FPSR: u32 = 33;
pub const HV_REG_CPSR: u32 = 34;

// System registers (hv_sys_reg_t).
pub const HV_SYS_REG_SCTLR_EL1: u16 = 0xc080;
pub const HV_SYS_REG_CPACR_EL1: u16 = 0xc082;
pub const HV_SYS_REG_TTBR0_EL1: u16 = 0xc100;
pub const HV_SYS_REG_TCR_EL1: u16 = 0xc102;
pub const HV_SYS_REG_SPSR_EL1: u16 = 0xc200;
pub const HV_SYS_REG_ELR_EL1: u16 = 0xc201;
pub const HV_SYS_REG_SP_EL0: u16 = 0xc208;
pub const HV_SYS_REG_ESR_EL1: u16 = 0xc290;
pub const HV_SYS_REG_FAR_EL1: u16 = 0xc300;
pub const HV_SYS_REG_MAIR_EL1: u16 = 0xc510;
pub const HV_SYS_REG_VBAR_EL1: u16 = 0xc600;
pub const HV_SYS_REG_TPIDR_EL0: u16 = 0xde82;
pub const HV_SYS_REG_SP_EL1: u16 = 0xe208;
pub const HV_SYS_REG_CNTKCTL_EL1: u16 = 0xc708;
pub const HV_SYS_REG_TPIDRRO_EL0: u16 = 0xde83;

/// hv_simd_fp_reg_t: Q0..Q31.
pub const HV_SIMD_FP_REG_Q0: u32 = 0;

#[link(name = "Hypervisor", kind = "framework")]
unsafe extern "C" {
    pub fn hv_vm_create(config: *mut c_void) -> hv_return_t;
    pub fn hv_vm_destroy() -> hv_return_t;
    pub fn hv_vm_map(addr: *mut c_void, ipa: u64, size: usize, flags: u64) -> hv_return_t;
    pub fn hv_vm_unmap(ipa: u64, size: usize) -> hv_return_t;
    pub fn hv_vm_get_max_vcpu_count(count: *mut u32) -> hv_return_t;
    pub fn hv_vcpu_create(
        vcpu: *mut hv_vcpu_t,
        exit: *mut *const hv_vcpu_exit_t,
        config: *mut c_void,
    ) -> hv_return_t;
    pub fn hv_vcpu_destroy(vcpu: hv_vcpu_t) -> hv_return_t;
    pub fn hv_vcpu_run(vcpu: hv_vcpu_t) -> hv_return_t;
    pub fn hv_vcpus_exit(vcpus: *const hv_vcpu_t, count: u32) -> hv_return_t;
    pub fn hv_vcpu_get_reg(vcpu: hv_vcpu_t, reg: u32, value: *mut u64) -> hv_return_t;
    pub fn hv_vcpu_set_reg(vcpu: hv_vcpu_t, reg: u32, value: u64) -> hv_return_t;
    pub fn hv_vcpu_get_sys_reg(vcpu: hv_vcpu_t, reg: u16, value: *mut u64) -> hv_return_t;
    pub fn hv_vcpu_set_sys_reg(vcpu: hv_vcpu_t, reg: u16, value: u64) -> hv_return_t;
    /// `value` points to a 16-byte (16-aligned) vector.
    pub fn hv_vcpu_get_simd_fp_reg(vcpu: hv_vcpu_t, reg: u32, value: *mut u128) -> hv_return_t;
    /// Takes the vector by value in v0, which stable Rust cannot express in
    /// FFI; only ever called through `set_simd_fp_reg`.
    fn hv_vcpu_set_simd_fp_reg();
}

/// Calls `hv_vcpu_set_simd_fp_reg(vcpu, reg, value)` with the 128-bit vector
/// passed in v0 per AAPCS64.
pub fn set_simd_fp_reg(vcpu: hv_vcpu_t, reg: u32, value: u128) -> hv_return_t {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "fmov d0, {lo}",
            "mov v0.d[1], {hi}",
            "bl {f}",
            lo = in(reg) value as u64,
            hi = in(reg) (value >> 64) as u64,
            f = sym hv_vcpu_set_simd_fp_reg,
            inlateout("x0") vcpu => ret,
            in("x1") reg as u64,
            clobber_abi("C"),
        );
    }
    ret as hv_return_t
}

pub fn check(what: &str, ret: hv_return_t) {
    if ret != HV_SUCCESS {
        panic!("{what} failed: hv_return_t = {ret:#x}");
    }
}
