//! Windows backend: Windows Hypervisor Platform (WinHvPlatform.dll).
//!
//! x86_64 guests run at CPL 3. `EFER.SCE` stays clear, so `syscall` raises
//! `#UD`. That exception is intercepted and reported as `Exit::Syscall` with
//! RIP moved two bytes forward; the guest never leaves ring 3, so there is no
//! `sysret` to emulate. The IDT points every vector at an `hlt` stub in the
//! kernel window, which turns an exception the bitmap missed into a halt exit
//! instead of a triple fault.
//!
//! Windows on ARM is rejected. windows-sys 0.61 exposes saved-state
//! `ARM64_Register*` ids, not the WHP `WHvArm64Register*` names
//! `WHvSetVirtualProcessorRegisters` takes.

#[cfg(target_arch = "aarch64")]
mod imp {
    use super::super::{Hypervisor, Vcpu};
    use crate::mem::GuestMem;

    pub struct Whp;

    impl Whp {
        pub fn new(_mem: &GuestMem) -> Result<Self, String> {
            // Keep the shared x86 tables referenced so this target still typechecks them.
            let _ = super::super::x86::EFER_LONG;
            Err(unsupported())
        }
    }

    impl Hypervisor for Whp {
        fn create_vcpu(&self, _entry: u64, _stack: u64) -> Result<Box<dyn Vcpu>, String> {
            Err(unsupported())
        }
    }

    fn unsupported() -> String {
        "not yet supported on Windows on ARM (windows-sys 0.61 has no WHP ARM64 register names)"
            .into()
    }
}

#[cfg(target_arch = "x86_64")]
mod imp {
    use super::super::x86;
    use super::super::{Exit, Hypervisor, SyscallRegs, Vcpu};
    use crate::mem::{BLOCK, GuestMem, MEM_SIZE};
    use std::ffi::c_void;
    use std::ptr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use windows_sys::Win32::System::Hypervisor::{
        WHV_CAPABILITY, WHV_EXTENDED_VM_EXITS, WHV_PARTITION_HANDLE, WHV_PARTITION_PROPERTY,
        WHV_PROCESSOR_XSAVE_FEATURES, WHV_REGISTER_NAME, WHV_REGISTER_VALUE,
        WHV_RUN_VP_EXIT_CONTEXT, WHV_VP_EXCEPTION_CONTEXT, WHV_X64_FP_CONTROL_STATUS_REGISTER,
        WHV_X64_FP_CONTROL_STATUS_REGISTER_0, WHV_X64_FP_CONTROL_STATUS_REGISTER_0_0,
        WHV_X64_SEGMENT_REGISTER, WHV_X64_SEGMENT_REGISTER_0, WHV_X64_TABLE_REGISTER,
        WHV_X64_XMM_CONTROL_STATUS_REGISTER, WHV_X64_XMM_CONTROL_STATUS_REGISTER_0,
        WHV_X64_XMM_CONTROL_STATUS_REGISTER_0_0, WHvCapabilityCodeHypervisorPresent,
        WHvCapabilityCodeProcessorFeatures, WHvCapabilityCodeProcessorXsaveFeatures,
        WHvCreatePartition, WHvCreateVirtualProcessor, WHvDeletePartition,
        WHvDeleteVirtualProcessor, WHvGetCapability, WHvGetVirtualProcessorRegisters,
        WHvMapGpaRange, WHvMapGpaRangeFlagExecute, WHvMapGpaRangeFlagRead, WHvMapGpaRangeFlagWrite,
        WHvPartitionPropertyCodeExceptionExitBitmap, WHvPartitionPropertyCodeExtendedVmExits,
        WHvPartitionPropertyCodeLocalApicEmulationMode, WHvPartitionPropertyCodeProcessorCount,
        WHvPartitionPropertyCodeProcessorXsaveFeatures, WHvRunVirtualProcessor,
        WHvRunVpExitReasonCanceled, WHvRunVpExitReasonException,
        WHvRunVpExitReasonInvalidVpRegisterValue, WHvRunVpExitReasonMemoryAccess,
        WHvRunVpExitReasonNone, WHvRunVpExitReasonUnrecoverableException,
        WHvRunVpExitReasonUnsupportedFeature, WHvRunVpExitReasonX64Halt,
        WHvRunVpExitReasonX64IoPortAccess, WHvSetPartitionProperty,
        WHvSetVirtualProcessorRegisters, WHvSetupPartition, WHvX64ExceptionTypeDivideErrorFault,
        WHvX64ExceptionTypeDoubleFaultAbort, WHvX64ExceptionTypeGeneralProtectionFault,
        WHvX64ExceptionTypeInvalidOpcodeFault, WHvX64ExceptionTypePageFault,
        WHvX64LocalApicEmulationModeNone, WHvX64RegisterCr0, WHvX64RegisterCr3, WHvX64RegisterCr4,
        WHvX64RegisterCs, WHvX64RegisterDs, WHvX64RegisterEfer, WHvX64RegisterEs,
        WHvX64RegisterFpControlStatus, WHvX64RegisterFs, WHvX64RegisterGdtr, WHvX64RegisterGs,
        WHvX64RegisterIdtr, WHvX64RegisterPat, WHvX64RegisterR8, WHvX64RegisterR9,
        WHvX64RegisterR10, WHvX64RegisterRax, WHvX64RegisterRdi, WHvX64RegisterRdx,
        WHvX64RegisterRflags, WHvX64RegisterRip, WHvX64RegisterRsi, WHvX64RegisterRsp,
        WHvX64RegisterSs, WHvX64RegisterTr, WHvX64RegisterXCr0, WHvX64RegisterXmmControlStatus,
    };

    /// `WHV_EXTENDED_VM_EXITS` on x64 is Cpuid, Msr, then ExceptionExit.
    const EXCEPTION_EXIT: u64 = 1 << 2;
    /// `HRESULT_FROM_WIN32(ERROR_CANCELLED)`.
    const ERROR_CANCELLED: u32 = 0x8007_04C7;
    const VP: u32 = 0;
    /// Rip through XCR0, plus the two FPU control registers.
    const REG_CAP: usize = 20;
    /// SDK `sizeof(WHV_RUN_VP_EXIT_CONTEXT)` on x64. The type is 16-aligned there;
    /// windows-sys 0.61 drops that alignment, so the buffer below restores it.
    const EXIT_CONTEXT_SIZE: usize = 224;

    const SYSCALL_NAMES: [WHV_REGISTER_NAME; 7] = [
        WHvX64RegisterRax,
        WHvX64RegisterRdi,
        WHvX64RegisterRsi,
        WHvX64RegisterRdx,
        WHvX64RegisterR10,
        WHvX64RegisterR8,
        WHvX64RegisterR9,
    ];

    /// The SDK aligns `WHV_REGISTER_VALUE` to 16. windows-sys 0.61 does not, so
    /// every buffer passed to the register API is wrapped in this.
    #[repr(C, align(16))]
    struct AlignedRegs {
        values: [WHV_REGISTER_VALUE; REG_CAP],
    }

    const _: () = assert!(size_of::<WHV_REGISTER_VALUE>() == 16);
    const _: () = assert!(align_of::<AlignedRegs>() == 16);
    const _: () = assert!(size_of::<WHV_RUN_VP_EXIT_CONTEXT>() == EXIT_CONTEXT_SIZE);

    /// `WHV_RUN_VP_EXIT_CONTEXT` is `DECLSPEC` 16-aligned in the SDK (it contains
    /// `WHV_UINT128`). windows-sys gives the union align 8, and an 8-aligned
    /// buffer faults inside `WHvRunVirtualProcessor` on a real machine.
    #[repr(C, align(16))]
    struct AlignedExit {
        context: WHV_RUN_VP_EXIT_CONTEXT,
    }

    const _: () = assert!(align_of::<AlignedExit>() == 16);

    struct RegList {
        names: [WHV_REGISTER_NAME; REG_CAP],
        values: AlignedRegs,
        len: usize,
    }

    impl RegList {
        fn new() -> Self {
            Self {
                names: [0; REG_CAP],
                values: AlignedRegs {
                    values: [WHV_REGISTER_VALUE::default(); REG_CAP],
                },
                len: 0,
            }
        }

        fn push(&mut self, name: WHV_REGISTER_NAME, value: WHV_REGISTER_VALUE) {
            assert!(self.len < REG_CAP);
            self.names[self.len] = name;
            self.values.values[self.len] = value;
            self.len += 1;
        }
    }

    struct Partition {
        handle: WHV_PARTITION_HANDLE,
        vp: AtomicBool,
    }

    impl Drop for Partition {
        fn drop(&mut self) {
            if self.handle == 0 {
                return;
            }
            delete_vp(self);
            let _ = unsafe { WHvDeletePartition(self.handle) };
        }
    }

    /// Deletes the partition if `new` fails before `Whp` owns it.
    struct PartitionGuard(WHV_PARTITION_HANDLE);

    impl PartitionGuard {
        fn handle(&self) -> WHV_PARTITION_HANDLE {
            self.0
        }

        fn release(mut self) -> WHV_PARTITION_HANDLE {
            let handle = self.0;
            self.0 = 0;
            handle
        }
    }

    impl Drop for PartitionGuard {
        fn drop(&mut self) {
            if self.0 != 0 {
                let _ = unsafe { WHvDeletePartition(self.0) };
            }
        }
    }

    pub struct Whp {
        partition: Arc<Partition>,
        /// Host mapping of GPA 0. `GuestMem` outlives every vCPU `main` creates.
        host: *const u8,
        /// Set when the partition accepted XSAVE. `None` keeps SSE without XCR0.
        xcr0: Option<u64>,
        /// Host reports `RdWrFsGsSupport`. CR4.FSGSBASE is not set otherwise.
        fsgsbase: bool,
    }

    impl Whp {
        pub fn new(mem: &GuestMem) -> Result<Self, String> {
            hypervisor_present()?;
            let mut raw: WHV_PARTITION_HANDLE = 0;
            ok("WHvCreatePartition", unsafe {
                WHvCreatePartition(&mut raw)
            })?;
            let guard = PartitionGuard(raw);
            let xcr0 = configure(guard.handle())?;
            ok("WHvSetupPartition", unsafe {
                WHvSetupPartition(guard.handle())
            })?;
            ok("WHvMapGpaRange", unsafe {
                WHvMapGpaRange(
                    guard.handle(),
                    mem.host_ptr().cast(),
                    0,
                    MEM_SIZE,
                    WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite | WHvMapGpaRangeFlagExecute,
                )
            })?;
            build_tables(mem);
            Ok(Whp {
                partition: Arc::new(Partition {
                    handle: guard.release(),
                    vp: AtomicBool::new(false),
                }),
                host: mem.host_ptr() as *const u8,
                xcr0,
                fsgsbase: processor_has_fsgsbase(),
            })
        }

        fn program(&self, entry: u64, stack: u64) -> Result<(), String> {
            let cr4 = x86::cr4_guest(self.fsgsbase, false);
            let cr4_xsave = x86::cr4_guest(self.fsgsbase, self.xcr0.is_some());
            let with_xsave = self.write_state(entry, stack, cr4_xsave, self.xcr0);
            if with_xsave.is_err() && self.xcr0.is_some() {
                // OSXSAVE is optional. OSFXSR and OSXMMEXCPT still enable SSE.
                return self.write_state(entry, stack, cr4, None);
            }
            with_xsave
        }

        fn write_state(
            &self,
            entry: u64,
            stack: u64,
            cr4: u64,
            xcr0: Option<u64>,
        ) -> Result<(), String> {
            let mut regs = RegList::new();
            regs.push(WHvX64RegisterRip, bits(entry));
            regs.push(WHvX64RegisterRsp, bits(stack));
            regs.push(WHvX64RegisterRflags, bits(x86::RFLAGS_USER));
            regs.push(WHvX64RegisterCs, code_seg());
            regs.push(WHvX64RegisterSs, data_seg(0));
            regs.push(WHvX64RegisterDs, data_seg(0));
            regs.push(WHvX64RegisterEs, data_seg(0));
            regs.push(WHvX64RegisterFs, data_seg(0));
            regs.push(WHvX64RegisterGs, data_seg(0));
            regs.push(WHvX64RegisterTr, tss_seg());
            regs.push(WHvX64RegisterGdtr, table(x86::GDT_BASE, x86::GDT_LIMIT));
            regs.push(WHvX64RegisterIdtr, table(x86::IDT_BASE, x86::IDT_LIMIT));
            regs.push(WHvX64RegisterCr0, bits(x86::CR0_LONG));
            regs.push(WHvX64RegisterCr3, bits(x86::PML4));
            // XCR0 before CR4, so OSXSAVE is not checked against the reset
            // XCR0 (x87 only). SSE would then raise #UD.
            if let Some(xcr0) = xcr0 {
                regs.push(WHvX64RegisterXCr0, bits(xcr0));
            }
            regs.push(WHvX64RegisterCr4, bits(cr4));
            regs.push(WHvX64RegisterEfer, bits(x86::EFER_LONG));
            regs.push(WHvX64RegisterPat, bits(x86::PAT_RESET));
            // Reset FCW is 0x0040, so with CR0.NE the first x87 op raises #MF.
            // Linux userspace expects FINIT's masks.
            regs.push(WHvX64RegisterFpControlStatus, fpu_control());
            regs.push(WHvX64RegisterXmmControlStatus, xmm_control());
            ok(
                "WHvSetVirtualProcessorRegisters",
                set_regs(self.partition.handle, &regs),
            )
        }
    }

    impl Hypervisor for Whp {
        fn create_vcpu(&self, entry: u64, stack: u64) -> Result<Box<dyn Vcpu>, String> {
            if self.partition.vp.swap(true, Ordering::AcqRel) {
                return Err("this partition already has a virtual processor".into());
            }
            if let Err(err) = ok("WHvCreateVirtualProcessor", unsafe {
                WHvCreateVirtualProcessor(self.partition.handle, VP, 0)
            }) {
                self.partition.vp.store(false, Ordering::Release);
                return Err(err);
            }
            if let Err(err) = self.program(entry, stack) {
                delete_vp(&self.partition);
                return Err(err);
            }
            Ok(Box::new(WhpVcpu {
                partition: Arc::clone(&self.partition),
                host: self.host,
            }))
        }
    }

    fn hypervisor_present() -> Result<(), String> {
        let mut cap = WHV_CAPABILITY::default();
        let hr = unsafe {
            WHvGetCapability(
                WHvCapabilityCodeHypervisorPresent,
                &mut cap as *mut _ as *mut c_void,
                size_of::<WHV_CAPABILITY>() as u32,
                ptr::null_mut(),
            )
        };
        let present = hr == 0 && unsafe { cap.HypervisorPresent } != 0;
        if present {
            Ok(())
        } else {
            Err("Windows Hypervisor Platform is not available. Enable \"Windows Hypervisor Platform\" in Windows Features.".into())
        }
    }

    fn configure(handle: WHV_PARTITION_HANDLE) -> Result<Option<u64>, String> {
        let mut property = WHV_PARTITION_PROPERTY::default();
        property.ProcessorCount = 1;
        set_property(handle, WHvPartitionPropertyCodeProcessorCount, property)?;

        property = WHV_PARTITION_PROPERTY::default();
        property.ExtendedVmExits = WHV_EXTENDED_VM_EXITS {
            AsUINT64: EXCEPTION_EXIT,
        };
        set_property(handle, WHvPartitionPropertyCodeExtendedVmExits, property)?;

        property = WHV_PARTITION_PROPERTY::default();
        property.ExceptionExitBitmap = x86::exception_exit_bitmap();
        set_property(
            handle,
            WHvPartitionPropertyCodeExceptionExitBitmap,
            property,
        )?;

        // No local APIC: an emulated timer would exit into `run` forever.
        property = WHV_PARTITION_PROPERTY::default();
        property.LocalApicEmulationMode = WHvX64LocalApicEmulationModeNone;
        set_property(
            handle,
            WHvPartitionPropertyCodeLocalApicEmulationMode,
            property,
        )?;

        Ok(xsave_state(handle))
    }

    fn xsave_state(handle: WHV_PARTITION_HANDLE) -> Option<u64> {
        let bits = xsave_features()?;
        let enabled = x86::xsave_property(bits)?;
        let mut property = WHV_PARTITION_PROPERTY::default();
        property.ProcessorXsaveFeatures = WHV_PROCESSOR_XSAVE_FEATURES { AsUINT64: enabled };
        set_property(
            handle,
            WHvPartitionPropertyCodeProcessorXsaveFeatures,
            property,
        )
        .ok()?;
        Some(x86::xcr0_from_xsave(enabled))
    }

    fn xsave_features() -> Option<u64> {
        let mut cap = WHV_CAPABILITY::default();
        let hr = unsafe {
            WHvGetCapability(
                WHvCapabilityCodeProcessorXsaveFeatures,
                &mut cap as *mut _ as *mut c_void,
                size_of::<WHV_CAPABILITY>() as u32,
                ptr::null_mut(),
            )
        };
        if hr != 0 {
            return None;
        }
        Some(unsafe { cap.ProcessorXsaveFeatures.AsUINT64 })
    }

    fn processor_has_fsgsbase() -> bool {
        let mut cap = WHV_CAPABILITY::default();
        let hr = unsafe {
            WHvGetCapability(
                WHvCapabilityCodeProcessorFeatures,
                &mut cap as *mut _ as *mut c_void,
                size_of::<WHV_CAPABILITY>() as u32,
                ptr::null_mut(),
            )
        };
        hr == 0 && unsafe { cap.ProcessorFeatures.AsUINT64 } & x86::PROCESSOR_FEATURE_FSGSBASE != 0
    }

    fn build_tables(mem: &GuestMem) {
        mem.kwrite(x86::PML4, x86::table_entry(x86::PDPT));
        mem.kwrite(x86::PDPT, x86::table_entry(x86::PD));
        for i in 0..(MEM_SIZE / BLOCK) {
            mem.kwrite(x86::PD + i * 8, x86::pde_for_block(i));
        }
        mem.kwrite(x86::GDT_BASE, gdt());
        let gate = x86::interrupt_gate(x86::STUB, x86::SEL_KCODE);
        for vector in 0..256u64 {
            mem.kwrite(x86::IDT_BASE + vector * 16, gate);
        }
        mem.kwrite(x86::TSS_BASE, x86::tss_bytes(x86::RSP0));
        mem.kwrite(x86::STUB, x86::HLT);
    }

    fn gdt() -> [u64; x86::GDT_ENTRIES as usize] {
        let mut gdt = [0u64; x86::GDT_ENTRIES as usize];
        gdt[sel_index(x86::SEL_KCODE)] = x86::code64_descriptor(0);
        gdt[sel_index(x86::SEL_KDATA)] = x86::data_descriptor(0);
        gdt[sel_index(x86::SEL_UDATA)] = x86::data_descriptor(3);
        gdt[sel_index(x86::SEL_UCODE)] = x86::code64_descriptor(3);
        let tss = x86::system_descriptor(x86::TSS_BASE, x86::TSS_LIMIT, x86::TSS_ACCESS);
        let tss_index = sel_index(x86::SEL_TSS);
        gdt[tss_index] = tss[0];
        gdt[tss_index + 1] = tss[1];
        gdt
    }

    fn sel_index(selector: u16) -> usize {
        (selector as usize & !3) / 8
    }

    fn set_property(
        handle: WHV_PARTITION_HANDLE,
        code: i32,
        property: WHV_PARTITION_PROPERTY,
    ) -> Result<(), String> {
        // The Microsoft long-mode sample passes the whole property union.
        ok("WHvSetPartitionProperty", unsafe {
            WHvSetPartitionProperty(
                handle,
                code,
                &property as *const _ as *const c_void,
                size_of::<WHV_PARTITION_PROPERTY>() as u32,
            )
        })
    }

    fn delete_vp(partition: &Partition) {
        if partition.vp.swap(false, Ordering::AcqRel) {
            let _ = unsafe { WHvDeleteVirtualProcessor(partition.handle, VP) };
        }
    }

    struct WhpVcpu {
        partition: Arc<Partition>,
        host: *const u8,
    }

    impl WhpVcpu {
        fn set_rip(&self, rip: u64) {
            let mut regs = RegList::new();
            regs.push(WHvX64RegisterRip, bits(rip));
            must(
                "WHvSetVirtualProcessorRegisters",
                set_regs(self.partition.handle, &regs),
            );
        }

        fn read_regs(&self, names: &[WHV_REGISTER_NAME]) -> AlignedRegs {
            assert!(names.len() <= REG_CAP);
            let mut values = AlignedRegs {
                values: [WHV_REGISTER_VALUE::default(); REG_CAP],
            };
            must("WHvGetVirtualProcessorRegisters", unsafe {
                WHvGetVirtualProcessorRegisters(
                    self.partition.handle,
                    VP,
                    names.as_ptr(),
                    names.len() as u32,
                    values.values.as_mut_ptr(),
                )
            });
            values
        }

        fn syscall_at(&self, rip: u64, ex: &WHV_VP_EXCEPTION_CONTEXT) -> bool {
            // The bytes at RIP are the instruction that raised #UD. The exit's
            // InstructionBytes are a hint: some builds leave the count at 0,
            // and a non-zero count can still be stale.
            if let Some(bytes) = self.insn_at(rip) {
                return x86::is_syscall(&bytes);
            }
            let n = (ex.InstructionByteCount as usize).min(ex.InstructionBytes.len());
            n >= 2 && x86::is_syscall(&ex.InstructionBytes[..n])
        }

        fn insn_at(&self, rip: u64) -> Option<[u8; 2]> {
            x86::checked_range(MEM_SIZE, rip, 2)?;
            let mut buf = [0u8; 2];
            // `checked_range` keeps both bytes inside the host mapping of GPA 0.
            unsafe {
                ptr::copy_nonoverlapping(self.host.add(rip as usize), buf.as_mut_ptr(), 2);
            }
            Some(buf)
        }

        fn on_exception(&self, rip: u64, ex: WHV_VP_EXCEPTION_CONTEXT) -> Exit {
            if ex.ExceptionType == WHvX64ExceptionTypeInvalidOpcodeFault as u8
                && self.syscall_at(rip, &ex)
            {
                let Some(next) = rip.checked_add(2) else {
                    return fault(rip, 0, "syscall at the top of the address space");
                };
                self.set_rip(next);
                return Exit::Syscall;
            }
            let addr = if ex.ExceptionType == WHvX64ExceptionTypePageFault as u8 {
                ex.ExceptionParameter
            } else {
                0
            };
            fault(
                rip,
                addr,
                &describe(ex.ExceptionType, ex.ErrorCode, ex.ExceptionParameter),
            )
        }
    }

    impl Vcpu for WhpVcpu {
        // windows-sys names the exit-reason constants in PascalCase.
        #[allow(non_upper_case_globals)]
        fn run(&mut self) -> Exit {
            loop {
                let mut exit = AlignedExit {
                    context: WHV_RUN_VP_EXIT_CONTEXT::default(),
                };
                let hr = unsafe {
                    WHvRunVirtualProcessor(
                        self.partition.handle,
                        VP,
                        &mut exit.context as *mut _ as *mut c_void,
                        size_of::<WHV_RUN_VP_EXIT_CONTEXT>() as u32,
                    )
                };
                if hr as u32 == ERROR_CANCELLED {
                    continue;
                }
                if hr != 0 {
                    return fault(
                        0,
                        0,
                        &format!("WHvRunVirtualProcessor failed: {:#010x}", hr as u32),
                    );
                }
                match exit.context.ExitReason {
                    WHvRunVpExitReasonCanceled | WHvRunVpExitReasonNone => continue,
                    WHvRunVpExitReasonException => {
                        let ex = unsafe { exit.context.Anonymous.VpException };
                        // #PF reports CR2 in ExceptionParameter.
                        return self.on_exception(exit.context.VpContext.Rip, ex);
                    }
                    _ => return unexpected(&exit.context),
                }
            }
        }

        fn syscall_regs(&self) -> SyscallRegs {
            let values = self.read_regs(&SYSCALL_NAMES);
            let reg = |i: usize| unsafe { values.values[i].Reg64 };
            SyscallRegs {
                nr: reg(0),
                args: [reg(1), reg(2), reg(3), reg(4), reg(5), reg(6)],
            }
        }

        fn set_syscall_return(&mut self, value: u64) {
            let mut regs = RegList::new();
            regs.push(WHvX64RegisterRax, bits(value));
            must(
                "WHvSetVirtualProcessorRegisters",
                set_regs(self.partition.handle, &regs),
            );
        }

        fn set_tls(&mut self, value: u64) {
            // `arch_prctl(ARCH_SET_FS)`: the selector stays the user data segment.
            let mut regs = RegList::new();
            regs.push(WHvX64RegisterFs, data_seg(value));
            must(
                "WHvSetVirtualProcessorRegisters",
                set_regs(self.partition.handle, &regs),
            );
        }
    }

    impl Drop for WhpVcpu {
        fn drop(&mut self) {
            delete_vp(&self.partition);
        }
    }

    #[allow(non_upper_case_globals)]
    fn unexpected(exit: &WHV_RUN_VP_EXIT_CONTEXT) -> Exit {
        let pc = exit.VpContext.Rip;
        let (addr, detail) = match exit.ExitReason {
            WHvRunVpExitReasonMemoryAccess => {
                let access = unsafe { exit.Anonymous.MemoryAccess };
                (
                    access.Gva,
                    format!("memory access gpa={:#x} gva={:#x}", access.Gpa, access.Gva),
                )
            }
            WHvRunVpExitReasonX64Halt => (
                0,
                "hlt in the kernel stub (exception was not intercepted)".into(),
            ),
            WHvRunVpExitReasonUnrecoverableException => (0, "unrecoverable exception".into()),
            WHvRunVpExitReasonInvalidVpRegisterValue => {
                (0, "invalid virtual processor register".into())
            }
            WHvRunVpExitReasonUnsupportedFeature => {
                let feature = unsafe { exit.Anonymous.UnsupportedFeature };
                (
                    0,
                    format!(
                        "unsupported feature code {} param {:#x}",
                        feature.FeatureCode, feature.FeatureParameter
                    ),
                )
            }
            WHvRunVpExitReasonX64IoPortAccess => {
                let io = unsafe { exit.Anonymous.IoPortAccess };
                (0, format!("io port {:#x}", io.PortNumber))
            }
            other => (0, format!("unexpected WHP exit {other}")),
        };
        fault(pc, addr, &detail)
    }

    #[allow(non_upper_case_globals)]
    fn describe(vector: u8, error: u32, param: u64) -> String {
        let name = match vector as i32 {
            WHvX64ExceptionTypeDivideErrorFault => "#DE",
            WHvX64ExceptionTypeDoubleFaultAbort => "#DF",
            WHvX64ExceptionTypeInvalidOpcodeFault => "#UD",
            WHvX64ExceptionTypeGeneralProtectionFault => "#GP",
            WHvX64ExceptionTypePageFault => "#PF",
            1 => "#DB",
            3 => "#BP",
            4 => "#OF",
            5 => "#BR",
            7 => "#NM",
            10 => "#TS",
            11 => "#NP",
            12 => "#SS",
            16 => "#MF",
            17 => "#AC",
            18 => "#MC",
            19 => "#XF",
            21 => "#CP",
            _ => "exception",
        };
        if vector == WHvX64ExceptionTypePageFault as u8 {
            format!("{name} error={error:#x} cr2={param:#x}")
        } else {
            format!("{name} vector {vector} error={error:#x}")
        }
    }

    fn fault(pc: u64, addr: u64, detail: &str) -> Exit {
        Exit::Fault {
            pc,
            addr,
            detail: detail.to_string(),
        }
    }

    fn fpu_control() -> WHV_REGISTER_VALUE {
        let mut value = WHV_REGISTER_VALUE::default();
        value.FpControlStatus = WHV_X64_FP_CONTROL_STATUS_REGISTER {
            Anonymous: WHV_X64_FP_CONTROL_STATUS_REGISTER_0 {
                FpControl: x86::FCW_LINUX,
                FpStatus: 0,
                // Abridged tag: 0 means every x87 register is empty (FINIT).
                FpTag: 0,
                Reserved: 0,
                LastFpOp: 0,
                Anonymous: WHV_X64_FP_CONTROL_STATUS_REGISTER_0_0 { LastFpRip: 0 },
            },
        };
        value
    }

    fn xmm_control() -> WHV_REGISTER_VALUE {
        let mut value = WHV_REGISTER_VALUE::default();
        value.XmmControlStatus = WHV_X64_XMM_CONTROL_STATUS_REGISTER {
            Anonymous: WHV_X64_XMM_CONTROL_STATUS_REGISTER_0 {
                Anonymous: WHV_X64_XMM_CONTROL_STATUS_REGISTER_0_0 { LastFpRdp: 0 },
                XmmStatusControl: x86::MXCSR_LINUX,
                XmmStatusControlMask: x86::MXCSR_MASK,
            },
        };
        value
    }

    fn set_regs(handle: WHV_PARTITION_HANDLE, regs: &RegList) -> windows_sys::core::HRESULT {
        debug_assert!((regs.values.values.as_ptr() as usize).is_multiple_of(16));
        unsafe {
            WHvSetVirtualProcessorRegisters(
                handle,
                VP,
                regs.names.as_ptr(),
                regs.len as u32,
                regs.values.values.as_ptr(),
            )
        }
    }

    fn code_seg() -> WHV_REGISTER_VALUE {
        segment(x86::SEL_UCODE, x86::code_attributes(3), 0, 0xFFFF_FFFF)
    }

    fn data_seg(base: u64) -> WHV_REGISTER_VALUE {
        segment(x86::SEL_UDATA, x86::data_attributes(3), base, 0xFFFF_FFFF)
    }

    fn tss_seg() -> WHV_REGISTER_VALUE {
        segment(
            x86::SEL_TSS,
            x86::tss_attributes(),
            x86::TSS_BASE,
            x86::TSS_LIMIT,
        )
    }

    fn segment(selector: u16, attributes: u16, base: u64, limit: u32) -> WHV_REGISTER_VALUE {
        let mut value = WHV_REGISTER_VALUE::default();
        value.Segment = WHV_X64_SEGMENT_REGISTER {
            Base: base,
            Limit: limit,
            Selector: selector,
            Anonymous: WHV_X64_SEGMENT_REGISTER_0 {
                Attributes: attributes,
            },
        };
        value
    }

    fn table(base: u64, limit: u16) -> WHV_REGISTER_VALUE {
        let mut value = WHV_REGISTER_VALUE::default();
        value.Table = WHV_X64_TABLE_REGISTER {
            Pad: [0; 3],
            Limit: limit,
            Base: base,
        };
        value
    }

    fn bits(v: u64) -> WHV_REGISTER_VALUE {
        let mut value = WHV_REGISTER_VALUE::default();
        value.Reg64 = v;
        value
    }

    fn ok(what: &str, hr: windows_sys::core::HRESULT) -> Result<(), String> {
        if hr == 0 {
            Ok(())
        } else {
            Err(format!("{what} failed: {:#010x}", hr as u32))
        }
    }

    fn must(what: &str, hr: windows_sys::core::HRESULT) {
        if let Err(err) = ok(what, hr) {
            panic!("{err}");
        }
    }
}

pub use imp::Whp;
