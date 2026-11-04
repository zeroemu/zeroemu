//! Windows backend: Windows Hypervisor Platform (WinHvPlatform.dll).
//!
//! x86_64 guests run at CPL 3. `EFER.SCE` stays clear, so `syscall` raises
//! `#UD`. That exception is intercepted and reported as `Exit::Syscall` with
//! RIP moved two bytes forward; the guest never leaves ring 3, so there is no
//! `sysret` to emulate. The IDT points every vector at an `hlt` stub in the
//! kernel window, which turns an exception the bitmap missed into a halt exit
//! instead of a triple fault.
//!
//! Page tables come from `mm`. A CR3 load flushes every translation (PCID and
//! PGE stay off). `flush_tlb` bumps a VM-wide generation. Each vCPU reloads
//! CR3 before its next guest entry if it has not seen that generation. The
//! flusher also cancels every vCPU inside `WHvRunVirtualProcessor` and waits
//! until it has left the guest or acknowledged the generation, so by the time
//! the flusher's next `run` returns no vCPU still holds a stale translation.
//! vCPUs blocked in host syscalls are not in the guest and reload lazily.
//!
//! `X86_64State.fpu` is the XSAVE area from
//! `WHvGetVirtualProcessorState(WHvVirtualProcessorStateTypeXsaveState)`
//! (falling back to `WHvGetVirtualProcessorXsaveState`): the 512-byte FXSAVE
//! legacy region, the 64-byte XSAVE header, then the components enabled in
//! XCR0 (YMM_Hi128 when AVX is advertised). Without XSAVE it is a 512-byte
//! FXSAVE image assembled from the FP and XMM registers. `set_state` writes
//! those bytes back.
//!
//! Windows on ARM is rejected. windows-sys 0.61 exposes saved-state
//! `ARM64_Register*` ids, not the WHP `WHvArm64Register*` names
//! `WHvSetVirtualProcessorRegisters` takes.

#[cfg(target_arch = "aarch64")]
mod imp {
    use super::super::{CpuState, Hypervisor, KernelPage, PageTableRoot, Vcpu};

    pub struct Whp;

    impl Whp {
        pub fn new() -> Result<Self, String> {
            Err(unsupported())
        }
    }

    impl Hypervisor for Whp {
        fn map_ram(&self, _host: *mut u8, _gpa: u64, _size: u64) -> Result<(), String> {
            Err(unsupported())
        }

        fn unmap_ram(&self, _gpa: u64, _size: u64) -> Result<(), String> {
            Err(unsupported())
        }

        fn kernel_pages(&self, _alloc: &mut dyn FnMut() -> (u64, *mut u8)) -> Vec<KernelPage> {
            Vec::new()
        }

        fn create_vcpu(
            &self,
            _root: PageTableRoot,
            _state: &CpuState,
        ) -> Result<Box<dyn Vcpu>, String> {
            Err(unsupported())
        }

        fn max_vcpus(&self) -> usize {
            0
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
    use super::super::{
        CpuState, Exit, Hypervisor, KernelPage, Kick, PageTableRoot, SyscallRegs, Vcpu, X86_64State,
    };
    use std::ffi::c_void;
    use std::ptr;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use windows_sys::Win32::System::Hypervisor::{
        WHV_CAPABILITY, WHV_EXTENDED_VM_EXITS, WHV_PARTITION_HANDLE, WHV_PARTITION_PROPERTY,
        WHV_PROCESSOR_XSAVE_FEATURES, WHV_REGISTER_NAME, WHV_REGISTER_VALUE,
        WHV_RUN_VP_EXIT_CONTEXT, WHV_VP_EXCEPTION_CONTEXT, WHV_X64_FP_CONTROL_STATUS_REGISTER,
        WHV_X64_FP_CONTROL_STATUS_REGISTER_0, WHV_X64_FP_CONTROL_STATUS_REGISTER_0_0,
        WHV_X64_SEGMENT_REGISTER, WHV_X64_SEGMENT_REGISTER_0, WHV_X64_TABLE_REGISTER,
        WHV_X64_XMM_CONTROL_STATUS_REGISTER, WHV_X64_XMM_CONTROL_STATUS_REGISTER_0,
        WHV_X64_XMM_CONTROL_STATUS_REGISTER_0_0, WHvCancelRunVirtualProcessor,
        WHvCapabilityCodeHypervisorPresent, WHvCapabilityCodeProcessorFeatures,
        WHvCapabilityCodeProcessorXsaveFeatures, WHvCreatePartition, WHvCreateVirtualProcessor,
        WHvDeletePartition, WHvDeleteVirtualProcessor, WHvGetCapability,
        WHvGetVirtualProcessorRegisters, WHvGetVirtualProcessorState,
        WHvGetVirtualProcessorXsaveState, WHvMapGpaRange, WHvMapGpaRangeFlagExecute,
        WHvMapGpaRangeFlagRead, WHvMapGpaRangeFlagWrite, WHvUnmapGpaRange,
        WHvPartitionPropertyCodeExceptionExitBitmap, WHvPartitionPropertyCodeExtendedVmExits,
        WHvPartitionPropertyCodeLocalApicEmulationMode, WHvPartitionPropertyCodeProcessorCount,
        WHvPartitionPropertyCodeProcessorXsaveFeatures, WHvRunVirtualProcessor,
        WHvRunVpExitReasonCanceled, WHvRunVpExitReasonException,
        WHvRunVpExitReasonInvalidVpRegisterValue, WHvRunVpExitReasonMemoryAccess,
        WHvRunVpExitReasonNone, WHvRunVpExitReasonUnrecoverableException,
        WHvRunVpExitReasonUnsupportedFeature, WHvRunVpExitReasonX64Halt,
        WHvRunVpExitReasonX64IoPortAccess, WHvSetPartitionProperty,
        WHvSetVirtualProcessorRegisters, WHvSetVirtualProcessorState,
        WHvSetVirtualProcessorXsaveState, WHvSetupPartition,
        WHvVirtualProcessorStateTypeXsaveState, WHvX64ExceptionTypeDivideErrorFault,
        WHvX64ExceptionTypeDoubleFaultAbort, WHvX64ExceptionTypeGeneralProtectionFault,
        WHvX64ExceptionTypeInvalidOpcodeFault, WHvX64ExceptionTypePageFault,
        WHvX64LocalApicEmulationModeNone, WHvX64RegisterCr0, WHvX64RegisterCr3, WHvX64RegisterCr4,
        WHvX64RegisterCs, WHvX64RegisterDs, WHvX64RegisterEfer, WHvX64RegisterEs,
        WHvX64RegisterFpControlStatus, WHvX64RegisterFpMmx0, WHvX64RegisterFs, WHvX64RegisterGdtr,
        WHvX64RegisterGs, WHvX64RegisterIdtr, WHvX64RegisterPat, WHvX64RegisterR8,
        WHvX64RegisterR9, WHvX64RegisterR10, WHvX64RegisterR11, WHvX64RegisterR12,
        WHvX64RegisterR13, WHvX64RegisterR14, WHvX64RegisterR15, WHvX64RegisterRax,
        WHvX64RegisterRbp, WHvX64RegisterRbx, WHvX64RegisterRcx, WHvX64RegisterRdi,
        WHvX64RegisterRdx, WHvX64RegisterRflags, WHvX64RegisterRip, WHvX64RegisterRsi,
        WHvX64RegisterRsp, WHvX64RegisterSs, WHvX64RegisterTr, WHvX64RegisterXCr0,
        WHvX64RegisterXmm0, WHvX64RegisterXmmControlStatus,
    };

    /// `WHV_EXTENDED_VM_EXITS` on x64 is Cpuid, Msr, then ExceptionExit.
    const EXCEPTION_EXIT: u64 = 1 << 2;
    /// `HRESULT_FROM_WIN32(ERROR_CANCELLED)`.
    const ERROR_CANCELLED: u32 = 0x8007_04C7;
    /// Ceiling on simultaneously live vCPUs. WHP's own maximum, if lower, wins.
    const VCPU_CAP: u32 = 64;
    /// GPR file plus the segment and control registers programmed at create.
    const REG_CAP: usize = 40;
    /// XSAVE area for x87 + SSE + AVX (832) with room for the header.
    const XSAVE_CAP: usize = 4096;
    /// Guest RAM ceiling. Matches `phys::PHYS_MAX`; not imported, because
    /// `phys` already depends on this module.
    const PHYS_MAX: u64 = 32 << 30;
    /// SDK `sizeof(WHV_RUN_VP_EXIT_CONTEXT)` on x64. The type is 16-aligned there;
    /// windows-sys 0.61 drops that alignment, so the buffer below restores it.
    const EXIT_CONTEXT_SIZE: usize = 224;

    const GPRS: [WHV_REGISTER_NAME; 16] = [
        WHvX64RegisterRax,
        WHvX64RegisterRcx,
        WHvX64RegisterRdx,
        WHvX64RegisterRbx,
        WHvX64RegisterRsp,
        WHvX64RegisterRbp,
        WHvX64RegisterRsi,
        WHvX64RegisterRdi,
        WHvX64RegisterR8,
        WHvX64RegisterR9,
        WHvX64RegisterR10,
        WHvX64RegisterR11,
        WHvX64RegisterR12,
        WHvX64RegisterR13,
        WHvX64RegisterR14,
        WHvX64RegisterR15,
    ];

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

    #[repr(C, align(64))]
    struct AlignedXsave {
        bytes: [u8; XSAVE_CAP],
    }

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

    struct VpSlot {
        /// Inside `WHvRunVirtualProcessor` (or about to enter it).
        in_guest: AtomicBool,
        /// Last TLB generation whose CR3 reload this vCPU has finished.
        seen: AtomicU64,
        /// `Kick::kick` wants `run` to return `Exit::Interrupted`.
        kicked: AtomicBool,
        alive: AtomicBool,
    }

    impl VpSlot {
        fn new() -> Self {
            Self {
                in_guest: AtomicBool::new(false),
                seen: AtomicU64::new(0),
                kicked: AtomicBool::new(false),
                alive: AtomicBool::new(false),
            }
        }
    }

    struct Shared {
        handle: WHV_PARTITION_HANDLE,
        /// Host address of guest-physical 0. Chunks from `map_ram` are contiguous.
        host_base: AtomicU64,
        tlb_gen: AtomicU64,
        slots: Vec<VpSlot>,
        free: Mutex<Vec<u32>>,
        /// `Some` when the partition accepted XSAVE. `None` keeps SSE without XCR0.
        xcr0: Option<u64>,
        /// Host reports `RdWrFsGsSupport`. CR4.FSGSBASE is not set otherwise.
        fsgsbase: bool,
    }

    impl Drop for Shared {
        fn drop(&mut self) {
            if self.handle == 0 {
                return;
            }
            for (i, slot) in self.slots.iter().enumerate() {
                if slot.alive.swap(false, Ordering::AcqRel) {
                    let _ = unsafe { WHvDeleteVirtualProcessor(self.handle, i as u32) };
                }
            }
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
        shared: Arc<Shared>,
    }

    impl Whp {
        pub fn new() -> Result<Self, String> {
            hypervisor_present()?;
            let mut raw: WHV_PARTITION_HANDLE = 0;
            ok("WHvCreatePartition", unsafe {
                WHvCreatePartition(&mut raw)
            })?;
            let guard = PartitionGuard(raw);
            let (count, xcr0) = configure(guard.handle())?;
            ok("WHvSetupPartition", unsafe {
                WHvSetupPartition(guard.handle())
            })?;
            let slots = (0..count).map(|_| VpSlot::new()).collect();
            Ok(Whp {
                shared: Arc::new(Shared {
                    handle: guard.release(),
                    host_base: AtomicU64::new(0),
                    tlb_gen: AtomicU64::new(0),
                    slots,
                    free: Mutex::new((0..count).rev().collect()),
                    xcr0,
                    fsgsbase: processor_has_fsgsbase(),
                }),
            })
        }
    }

    impl Hypervisor for Whp {
        fn map_ram(&self, host: *mut u8, gpa: u64, size: u64) -> Result<(), String> {
            let base = (host as u64).wrapping_sub(gpa);
            let prev = self.shared.host_base.load(Ordering::Acquire);
            // Guest RAM is one contiguous host reservation. Device memory
            // (GPU blobs above PHYS_MAX) is a separate host allocation; WHP
            // maps it, but guest_u64 only translates the RAM window.
            if prev == 0 {
                self.shared.host_base.store(base, Ordering::Release);
            } else if prev != base && gpa < crate::phys::PHYS_MAX {
                return Err("guest RAM is not one contiguous host mapping".into());
            }
            ok("WHvMapGpaRange", unsafe {
                WHvMapGpaRange(
                    self.shared.handle,
                    host.cast(),
                    gpa,
                    size,
                    WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite | WHvMapGpaRangeFlagExecute,
                )
            })
        }

        fn unmap_ram(&self, gpa: u64, size: u64) -> Result<(), String> {
            ok("WHvUnmapGpaRange", unsafe { WHvUnmapGpaRange(self.shared.handle, gpa, size) })
        }

        fn kernel_pages(&self, alloc: &mut dyn FnMut() -> (u64, *mut u8)) -> Vec<KernelPage> {
            let mut pages = Vec::with_capacity(5);
            for (va, exec) in x86::kernel_slots() {
                let (gpa, host) = alloc();
                fill_kernel_page(va, host);
                pages.push(KernelPage { va, gpa, exec });
            }
            pages
        }

        fn create_vcpu(
            &self,
            root: PageTableRoot,
            state: &CpuState,
        ) -> Result<Box<dyn Vcpu>, String> {
            let index = self.shared.free.lock().unwrap().pop().ok_or_else(|| {
                format!(
                    "virtual processor limit ({}) reached",
                    self.shared.slots.len()
                )
            })?;
            self.shared.slots[index as usize]
                .kicked
                .store(false, Ordering::Relaxed);
            self.shared.slots[index as usize]
                .seen
                .store(0, Ordering::Relaxed);
            self.shared.slots[index as usize]
                .in_guest
                .store(false, Ordering::Relaxed);
            if let Err(err) = ok("WHvCreateVirtualProcessor", unsafe {
                WHvCreateVirtualProcessor(self.shared.handle, index, 0)
            }) {
                self.shared.free.lock().unwrap().push(index);
                return Err(err);
            }
            self.shared.slots[index as usize]
                .alive
                .store(true, Ordering::Release);
            let mut vcpu = WhpVcpu {
                shared: Arc::clone(&self.shared),
                index,
                cr3: root.root,
            };
            if let Err(err) = vcpu.program(state) {
                drop(vcpu);
                return Err(err);
            }
            Ok(Box::new(vcpu))
        }

        fn max_vcpus(&self) -> usize {
            self.shared.slots.len()
        }
    }

    fn fill_kernel_page(va: u64, host: *mut u8) {
        // `host` is the page `alloc` just returned; each write stays inside it.
        unsafe {
            match va {
                x86::GDT_VA => {
                    let gdt = x86::gdt();
                    for (i, entry) in gdt.iter().enumerate() {
                        (host as *mut u64).add(i).write(*entry);
                    }
                }
                x86::IDT_VA => {
                    let gate = x86::idt_gate();
                    for vector in 0..256 {
                        (host as *mut u64).add(vector * 2).write(gate[0]);
                        (host as *mut u64).add(vector * 2 + 1).write(gate[1]);
                    }
                }
                x86::TSS_VA => {
                    let tss = x86::tss_bytes(x86::RSP0);
                    ptr::copy_nonoverlapping(tss.as_ptr(), host, tss.len());
                }
                x86::STUB_VA => host.write(x86::HLT),
                _ => {}
            }
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

    /// Processor count is fixed at partition creation. Try `VCPU_CAP` and step
    /// down until WHP accepts a count; that count is `max_vcpus`.
    fn configure(handle: WHV_PARTITION_HANDLE) -> Result<(u32, Option<u64>), String> {
        let mut count = VCPU_CAP;
        loop {
            let mut property = WHV_PARTITION_PROPERTY::default();
            property.ProcessorCount = count;
            if set_property(handle, WHvPartitionPropertyCodeProcessorCount, property).is_ok() {
                break;
            }
            if count == 1 {
                return Err("WHvSetPartitionProperty(ProcessorCount) failed".into());
            }
            count /= 2;
        }

        let mut property = WHV_PARTITION_PROPERTY::default();
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

        Ok((count, xsave_state(handle)))
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

    struct WhpVcpu {
        shared: Arc<Shared>,
        index: u32,
        cr3: u64,
    }

    struct WhpKick {
        shared: Arc<Shared>,
        index: u32,
    }

    impl Kick for WhpKick {
        fn kick(&self) {
            let slot = &self.shared.slots[self.index as usize];
            slot.kicked.store(true, Ordering::Release);
            // A cancel issued before `WHvRunVirtualProcessor` is lost. Retry
            // while the vCPU publishes that it is inside the call.
            while slot.in_guest.load(Ordering::Acquire) && slot.kicked.load(Ordering::Acquire) {
                let _ = unsafe { WHvCancelRunVirtualProcessor(self.shared.handle, self.index, 0) };
                std::thread::yield_now();
            }
        }
    }

    enum Stop {
        Leave(Exit),
        /// `WHvCancelRunVirtualProcessor` (TLB shootdown or kick).
        Canceled,
    }

    impl WhpVcpu {
        fn slot(&self) -> &VpSlot {
            &self.shared.slots[self.index as usize]
        }

        fn program(&mut self, state: &CpuState) -> Result<(), String> {
            let cr4 = x86::cr4_guest(self.shared.fsgsbase, false);
            let cr4_xsave = x86::cr4_guest(self.shared.fsgsbase, self.shared.xcr0.is_some());
            let with_xsave = self.write_controls(cr4_xsave, self.shared.xcr0);
            if with_xsave.is_err() && self.shared.xcr0.is_some() {
                // OSXSAVE is optional. OSFXSR and OSXMMEXCPT still enable SSE.
                self.write_controls(cr4, None)?;
            } else {
                with_xsave?;
            }
            self.write_user(state)?;
            let CpuState::X86_64(s) = state else {
                return Err("aarch64 state on an x86_64 vCPU".into());
            };
            if !s.fpu.is_empty() {
                self.write_xsave(&s.fpu)?;
            }
            let generation = self.shared.tlb_gen.load(Ordering::Acquire);
            self.slot().seen.store(generation, Ordering::Release);
            Ok(())
        }

        fn write_controls(&self, cr4: u64, xcr0: Option<u64>) -> Result<(), String> {
            let mut regs = RegList::new();
            regs.push(WHvX64RegisterCs, code_seg());
            regs.push(WHvX64RegisterSs, data_seg(0));
            regs.push(WHvX64RegisterDs, data_seg(0));
            regs.push(WHvX64RegisterEs, data_seg(0));
            regs.push(WHvX64RegisterFs, data_seg(0));
            regs.push(WHvX64RegisterGs, data_seg(0));
            regs.push(WHvX64RegisterTr, tss_seg());
            regs.push(WHvX64RegisterGdtr, table(x86::GDT_VA, x86::GDT_LIMIT));
            regs.push(WHvX64RegisterIdtr, table(x86::IDT_VA, x86::IDT_LIMIT));
            regs.push(WHvX64RegisterCr0, bits(x86::CR0_LONG));
            regs.push(WHvX64RegisterCr3, bits(self.cr3));
            // XCR0 before CR4, so OSXSAVE is not checked against the reset
            // XCR0 (x87 only). SSE would then raise #UD.
            if let Some(xcr0) = xcr0 {
                regs.push(WHvX64RegisterXCr0, bits(xcr0));
            }
            regs.push(WHvX64RegisterCr4, bits(cr4));
            regs.push(WHvX64RegisterEfer, bits(x86::EFER_LONG));
            regs.push(WHvX64RegisterPat, bits(x86::PAT_RESET));
            // Reset FCW is 0x0040, so with CR0.NE the first x87 op raises #MF.
            // Linux userspace expects FINIT's masks. An XSAVE image, when the
            // caller has one, overwrites these.
            regs.push(
                WHvX64RegisterFpControlStatus,
                fpu_control(x86::FCW_LINUX, 0, 0, 0, 0),
            );
            regs.push(
                WHvX64RegisterXmmControlStatus,
                xmm_control(x86::MXCSR_LINUX, x86::MXCSR_MASK, 0),
            );
            ok("WHvSetVirtualProcessorRegisters", self.set_regs(&regs))
        }

        fn write_user(&self, state: &CpuState) -> Result<(), String> {
            let CpuState::X86_64(s) = state else {
                return Err("aarch64 state on an x86_64 vCPU".into());
            };
            let mut regs = RegList::new();
            for (i, &name) in GPRS.iter().enumerate() {
                regs.push(name, bits(s.gpr[i]));
            }
            regs.push(WHvX64RegisterRip, bits(s.rip));
            // Bit 1 is reserved and must be set; IF stays on for ring 3.
            regs.push(WHvX64RegisterRflags, bits(s.rflags | x86::RFLAGS_USER));
            regs.push(WHvX64RegisterFs, data_seg(s.fs_base));
            regs.push(WHvX64RegisterGs, data_seg(s.gs_base));
            ok("WHvSetVirtualProcessorRegisters", self.set_regs(&regs))
        }

        fn write_cr3(&self) {
            let mut regs = RegList::new();
            regs.push(WHvX64RegisterCr3, bits(self.cr3));
            must("WHvSetVirtualProcessorRegisters", self.set_regs(&regs));
        }

        fn sync_tlb(&self) {
            let generation = self.shared.tlb_gen.load(Ordering::Acquire);
            if self.slot().seen.load(Ordering::Relaxed) == generation {
                return;
            }
            self.write_cr3();
            self.slot().seen.store(generation, Ordering::Release);
        }

        fn set_regs(&self, regs: &RegList) -> windows_sys::core::HRESULT {
            debug_assert!((regs.values.values.as_ptr() as usize).is_multiple_of(16));
            unsafe {
                WHvSetVirtualProcessorRegisters(
                    self.shared.handle,
                    self.index,
                    regs.names.as_ptr(),
                    regs.len as u32,
                    regs.values.values.as_ptr(),
                )
            }
        }

        fn read_regs(&self, names: &[WHV_REGISTER_NAME]) -> AlignedRegs {
            assert!(names.len() <= REG_CAP);
            let mut values = AlignedRegs {
                values: [WHV_REGISTER_VALUE::default(); REG_CAP],
            };
            must("WHvGetVirtualProcessorRegisters", unsafe {
                WHvGetVirtualProcessorRegisters(
                    self.shared.handle,
                    self.index,
                    names.as_ptr(),
                    names.len() as u32,
                    values.values.as_mut_ptr(),
                )
            });
            values
        }

        fn read_xsave(&self) -> Vec<u8> {
            let mut buf = AlignedXsave {
                bytes: [0; XSAVE_CAP],
            };
            let mut written = 0u32;
            let hr = unsafe {
                WHvGetVirtualProcessorState(
                    self.shared.handle,
                    self.index,
                    WHvVirtualProcessorStateTypeXsaveState,
                    buf.bytes.as_mut_ptr().cast(),
                    XSAVE_CAP as u32,
                    &mut written,
                )
            };
            if hr == 0 && (512..=XSAVE_CAP).contains(&(written as usize)) {
                return buf.bytes[..written as usize].to_vec();
            }
            written = 0;
            let hr = unsafe {
                WHvGetVirtualProcessorXsaveState(
                    self.shared.handle,
                    self.index,
                    buf.bytes.as_mut_ptr().cast(),
                    XSAVE_CAP as u32,
                    &mut written,
                )
            };
            if hr == 0 && (512..=XSAVE_CAP).contains(&(written as usize)) {
                return buf.bytes[..written as usize].to_vec();
            }
            self.fxsave_image()
        }

        fn write_xsave(&self, image: &[u8]) -> Result<(), String> {
            if image.is_empty() {
                return Ok(());
            }
            if image.len() <= XSAVE_CAP {
                let mut buf = AlignedXsave {
                    bytes: [0; XSAVE_CAP],
                };
                buf.bytes[..image.len()].copy_from_slice(image);
                let hr = unsafe {
                    WHvSetVirtualProcessorState(
                        self.shared.handle,
                        self.index,
                        WHvVirtualProcessorStateTypeXsaveState,
                        buf.bytes.as_ptr().cast(),
                        image.len() as u32,
                    )
                };
                if hr == 0 {
                    return Ok(());
                }
                let hr = unsafe {
                    WHvSetVirtualProcessorXsaveState(
                        self.shared.handle,
                        self.index,
                        buf.bytes.as_ptr().cast(),
                        image.len() as u32,
                    )
                };
                if hr == 0 {
                    return Ok(());
                }
            }
            if image.len() >= 512 {
                self.write_fxsave_regs(image);
                return Ok(());
            }
            Err(format!(
                "FPU image is {} bytes; XSAVE state was rejected",
                image.len()
            ))
        }

        /// 512-byte FXSAVE image from the individual FP/XMM registers.
        fn fxsave_image(&self) -> Vec<u8> {
            let fp_names = [
                WHvX64RegisterFpControlStatus,
                WHvX64RegisterXmmControlStatus,
                WHvX64RegisterFpMmx0,
                WHvX64RegisterFpMmx0 + 1,
                WHvX64RegisterFpMmx0 + 2,
                WHvX64RegisterFpMmx0 + 3,
                WHvX64RegisterFpMmx0 + 4,
                WHvX64RegisterFpMmx0 + 5,
                WHvX64RegisterFpMmx0 + 6,
                WHvX64RegisterFpMmx0 + 7,
            ];
            let mut names = [0; 26];
            names[..fp_names.len()].copy_from_slice(&fp_names);
            for i in 0..16 {
                names[fp_names.len() + i] = WHvX64RegisterXmm0 + i as i32;
            }
            let values = self.read_regs(&names);
            let mut image = vec![0u8; 512];
            let fp = unsafe { values.values[0].FpControlStatus.Anonymous };
            image[0..2].copy_from_slice(&fp.FpControl.to_le_bytes());
            image[2..4].copy_from_slice(&fp.FpStatus.to_le_bytes());
            image[4] = fp.FpTag;
            image[6..8].copy_from_slice(&fp.LastFpOp.to_le_bytes());
            let rip = unsafe { fp.Anonymous.LastFpRip };
            image[8..16].copy_from_slice(&rip.to_le_bytes());
            let xmm = unsafe { values.values[1].XmmControlStatus.Anonymous };
            let rdp = unsafe { xmm.Anonymous.LastFpRdp };
            image[16..24].copy_from_slice(&rdp.to_le_bytes());
            image[24..28].copy_from_slice(&xmm.XmmStatusControl.to_le_bytes());
            image[28..32].copy_from_slice(&xmm.XmmStatusControlMask.to_le_bytes());
            for i in 0..8 {
                let raw = unsafe { values.values[2 + i].Reg128.Anonymous };
                image[32 + i * 16..40 + i * 16].copy_from_slice(&raw.Low64.to_le_bytes());
                image[40 + i * 16..48 + i * 16].copy_from_slice(&raw.High64.to_le_bytes());
            }
            for i in 0..16 {
                let raw = unsafe { values.values[10 + i].Reg128.Anonymous };
                image[160 + i * 16..168 + i * 16].copy_from_slice(&raw.Low64.to_le_bytes());
                image[168 + i * 16..176 + i * 16].copy_from_slice(&raw.High64.to_le_bytes());
            }
            image
        }

        fn write_fxsave_regs(&self, image: &[u8]) {
            let mut regs = RegList::new();
            let cwd = u16::from_le_bytes(image[0..2].try_into().unwrap());
            let swd = u16::from_le_bytes(image[2..4].try_into().unwrap());
            let fop = u16::from_le_bytes(image[6..8].try_into().unwrap());
            let rip = u64::from_le_bytes(image[8..16].try_into().unwrap());
            regs.push(
                WHvX64RegisterFpControlStatus,
                fpu_control(cwd, swd, image[4], fop, rip),
            );
            let mxcsr = u32::from_le_bytes(image[24..28].try_into().unwrap());
            let mask = u32::from_le_bytes(image[28..32].try_into().unwrap());
            let rdp = u64::from_le_bytes(image[16..24].try_into().unwrap());
            regs.push(
                WHvX64RegisterXmmControlStatus,
                xmm_control(mxcsr, mask, rdp),
            );
            for i in 0..8 {
                regs.push(
                    WHvX64RegisterFpMmx0 + i as i32,
                    reg128(&image[32 + i * 16..48 + i * 16]),
                );
            }
            for i in 0..16 {
                regs.push(
                    WHvX64RegisterXmm0 + i as i32,
                    reg128(&image[160 + i * 16..176 + i * 16]),
                );
            }
            must("WHvSetVirtualProcessorRegisters", self.set_regs(&regs));
        }

        fn user_state(&self) -> X86_64State {
            let mut names = [0; 20];
            names[..16].copy_from_slice(&GPRS);
            names[16] = WHvX64RegisterRip;
            names[17] = WHvX64RegisterRflags;
            names[18] = WHvX64RegisterFs;
            names[19] = WHvX64RegisterGs;
            let values = self.read_regs(&names);
            let reg64 = |i: usize| unsafe { values.values[i].Reg64 };
            let mut gpr = [0u64; 16];
            for (i, slot) in gpr.iter_mut().enumerate() {
                *slot = reg64(i);
            }
            X86_64State {
                gpr,
                rip: reg64(16),
                rflags: reg64(17),
                fs_base: unsafe { values.values[18].Segment.Base },
                gs_base: unsafe { values.values[19].Segment.Base },
                fpu: self.read_xsave(),
            }
        }

        fn take_kick(&self) -> bool {
            self.slot().kicked.swap(false, Ordering::AcqRel)
        }

        fn guest_u64(&self, gpa: u64) -> Option<u64> {
            let base = self.shared.host_base.load(Ordering::Acquire);
            if base == 0 || gpa.checked_add(8)? > PHYS_MAX {
                return None;
            }
            Some(unsafe { ((base + gpa) as *const u64).read() })
        }

        /// 4-level walk of the current CR3. Large pages are accepted; this
        /// kernel only installs 4 KiB leaves.
        fn translate(&self, va: u64) -> Option<u64> {
            // Bits 63:47 must be all 0 or all 1.
            let high = va >> 47;
            if high != 0 && high != 0x1_ffff {
                return None;
            }
            let mut table = self.cr3 & 0x0000_ffff_ffff_f000;
            let shifts = [39u32, 30, 21, 12];
            for (level, shift) in shifts.iter().enumerate() {
                let index = (va >> shift) & 511;
                let entry = self.guest_u64(table + index * 8)?;
                if entry & 1 == 0 {
                    return None;
                }
                let addr = entry & 0x0000_ffff_ffff_f000;
                if level < 3 && entry & (1 << 7) != 0 {
                    let mask = (1u64 << shift) - 1;
                    return Some((addr & !mask) | (va & mask));
                }
                table = addr;
            }
            Some(table | (va & 0xfff))
        }

        fn insn_at(&self, rip: u64, ex: &WHV_VP_EXCEPTION_CONTEXT) -> [u8; 2] {
            if let Some(bytes) = self.guest_bytes(rip, 2) {
                return [bytes[0], bytes[1]];
            }
            let n = (ex.InstructionByteCount as usize).min(ex.InstructionBytes.len());
            if n >= 2 {
                [ex.InstructionBytes[0], ex.InstructionBytes[1]]
            } else {
                [0, 0]
            }
        }

        fn guest_bytes(&self, va: u64, len: usize) -> Option<Vec<u8>> {
            let base = self.shared.host_base.load(Ordering::Acquire);
            if base == 0 {
                return None;
            }
            let mut out = vec![0u8; len];
            let mut done = 0;
            while done < len {
                let gpa = self.translate(va + done as u64)?;
                if gpa >= PHYS_MAX {
                    return None;
                }
                let page_left = 0x1000 - (gpa & 0xfff) as usize;
                let chunk = (len - done).min(page_left);
                unsafe {
                    ptr::copy_nonoverlapping(
                        (base + gpa) as *const u8,
                        out.as_mut_ptr().add(done),
                        chunk,
                    );
                }
                done += chunk;
            }
            Some(out)
        }

        fn on_exception(&self, exit: &AlignedExit) -> Exit {
            let rip = exit.context.VpContext.Rip;
            let ex = unsafe { exit.context.Anonymous.VpException };
            let cpl = unsafe { exit.context.VpContext.ExecutionState.AsUINT16 } & 3;
            if ex.ExceptionType == WHvX64ExceptionTypeInvalidOpcodeFault as u8
                && x86::is_syscall(&self.insn_at(rip, &ex))
            {
                let Some(next) = rip.checked_add(2) else {
                    return fault(rip, 0, "syscall at the top of the address space");
                };
                let mut regs = RegList::new();
                regs.push(WHvX64RegisterRip, bits(next));
                must("WHvSetVirtualProcessorRegisters", self.set_regs(&regs));
                return Exit::Syscall;
            }
            if ex.ExceptionType == WHvX64ExceptionTypePageFault as u8 {
                let addr = ex.ExceptionParameter;
                // User #PF (CPL 3 and the error-code U/S bit). Resuming
                // re-executes the faulting instruction, so RIP stays put.
                if cpl == 3 && x86::pf_user(ex.ErrorCode) {
                    return Exit::PageFault {
                        pc: rip,
                        addr,
                        write: x86::pf_write(ex.ErrorCode),
                        exec: x86::pf_exec(ex.ErrorCode),
                    };
                }
                return fault(
                    rip,
                    addr,
                    &format!(
                        "supervisor #PF cpl={cpl} error={:#x} cr2={addr:#x}",
                        ex.ErrorCode
                    ),
                );
            }
            fault(
                rip,
                0,
                &describe(ex.ExceptionType, ex.ErrorCode, ex.ExceptionParameter),
            )
        }

        fn run_once(&self) -> Stop {
            let mut exit = AlignedExit {
                context: WHV_RUN_VP_EXIT_CONTEXT::default(),
            };
            let hr = unsafe {
                WHvRunVirtualProcessor(
                    self.shared.handle,
                    self.index,
                    &mut exit.context as *mut _ as *mut c_void,
                    size_of::<WHV_RUN_VP_EXIT_CONTEXT>() as u32,
                )
            };
            if hr as u32 == ERROR_CANCELLED {
                return Stop::Canceled;
            }
            if hr != 0 {
                return Stop::Leave(fault(
                    0,
                    0,
                    &format!("WHvRunVirtualProcessor failed: {:#010x}", hr as u32),
                ));
            }
            // windows-sys names the exit-reason constants in PascalCase.
            #[allow(non_upper_case_globals)]
            match exit.context.ExitReason {
                WHvRunVpExitReasonCanceled => Stop::Canceled,
                WHvRunVpExitReasonNone => Stop::Canceled,
                WHvRunVpExitReasonException => Stop::Leave(self.on_exception(&exit)),
                _ => Stop::Leave(unexpected(&exit.context)),
            }
        }
    }

    impl Vcpu for WhpVcpu {
        fn run(&mut self) -> Exit {
            loop {
                if self.take_kick() {
                    return Exit::Interrupted;
                }
                self.sync_tlb();
                let slot = self.slot();
                // Store-then-load against flush_tlb's increment-then-load: the
                // Dekker pattern, which needs SeqCst on all four operations,
                // or both sides could miss each other (we would enter with a
                // stale TLB while the flusher skips us).
                slot.in_guest.store(true, Ordering::SeqCst);
                let stale = self.shared.tlb_gen.load(Ordering::SeqCst)
                    != slot.seen.load(Ordering::Relaxed);
                let kicked = slot.kicked.load(Ordering::Acquire);
                if stale || kicked {
                    slot.in_guest.store(false, Ordering::Release);
                    continue;
                }
                let stop = self.run_once();
                self.slot().in_guest.store(false, Ordering::Release);
                match stop {
                    Stop::Canceled => {
                        if self.take_kick() {
                            return Exit::Interrupted;
                        }
                    }
                    Stop::Leave(exit) => return exit,
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
            must("WHvSetVirtualProcessorRegisters", self.set_regs(&regs));
        }

        fn state(&self) -> CpuState {
            CpuState::X86_64(Box::new(self.user_state()))
        }

        fn set_state(&mut self, state: &CpuState) {
            if let Err(err) = self.write_user(state) {
                panic!("{err}");
            }
            if let CpuState::X86_64(s) = state
                && !s.fpu.is_empty()
                && let Err(err) = self.write_xsave(&s.fpu)
            {
                panic!("{err}");
            }
        }

        fn set_page_tables(&mut self, root: PageTableRoot) {
            self.cr3 = root.root;
            self.write_cr3();
            let generation = self.shared.tlb_gen.load(Ordering::Acquire);
            self.slot().seen.store(generation, Ordering::Release);
        }

        fn flush_tlb(&mut self) {
            // SeqCst pairs with the entry check in run(); see there.
            let generation = self.shared.tlb_gen.fetch_add(1, Ordering::SeqCst) + 1;
            for (i, slot) in self.shared.slots.iter().enumerate() {
                if i == self.index as usize || !slot.alive.load(Ordering::Acquire) {
                    continue;
                }
                while slot.in_guest.load(Ordering::SeqCst)
                    && slot.seen.load(Ordering::Acquire) < generation
                {
                    let _ =
                        unsafe { WHvCancelRunVirtualProcessor(self.shared.handle, i as u32, 0) };
                    std::thread::yield_now();
                }
            }
        }

        fn kicker(&self) -> Arc<dyn Kick> {
            Arc::new(WhpKick {
                shared: Arc::clone(&self.shared),
                index: self.index,
            })
        }
    }

    impl Drop for WhpVcpu {
        fn drop(&mut self) {
            let slot = self.slot();
            slot.in_guest.store(false, Ordering::Release);
            slot.seen.store(u64::MAX, Ordering::Release);
            if slot.alive.swap(false, Ordering::AcqRel) {
                let _ = unsafe { WHvDeleteVirtualProcessor(self.shared.handle, self.index) };
                self.shared.free.lock().unwrap().push(self.index);
            }
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

    fn fpu_control(cwd: u16, swd: u16, tag: u8, fop: u16, rip: u64) -> WHV_REGISTER_VALUE {
        let mut value = WHV_REGISTER_VALUE::default();
        value.FpControlStatus = WHV_X64_FP_CONTROL_STATUS_REGISTER {
            Anonymous: WHV_X64_FP_CONTROL_STATUS_REGISTER_0 {
                FpControl: cwd,
                FpStatus: swd,
                FpTag: tag,
                Reserved: 0,
                LastFpOp: fop,
                Anonymous: WHV_X64_FP_CONTROL_STATUS_REGISTER_0_0 { LastFpRip: rip },
            },
        };
        value
    }

    fn xmm_control(mxcsr: u32, mask: u32, rdp: u64) -> WHV_REGISTER_VALUE {
        let mut value = WHV_REGISTER_VALUE::default();
        value.XmmControlStatus = WHV_X64_XMM_CONTROL_STATUS_REGISTER {
            Anonymous: WHV_X64_XMM_CONTROL_STATUS_REGISTER_0 {
                Anonymous: WHV_X64_XMM_CONTROL_STATUS_REGISTER_0_0 { LastFpRdp: rdp },
                XmmStatusControl: mxcsr,
                XmmStatusControlMask: mask,
            },
        };
        value
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
            x86::TSS_VA,
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

    fn reg128(bytes: &[u8]) -> WHV_REGISTER_VALUE {
        let mut value = WHV_REGISTER_VALUE::default();
        value.Reg128.Anonymous.Low64 = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        value.Reg128.Anonymous.High64 = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
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
