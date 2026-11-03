//! Placeholder while `whp.rs` (the Windows Hypervisor Platform backend, built
//! for the earlier identity-mapped memory model) is ported to paged memory:
//! `map_ram`, per-address-space page tables, full CPU state, and kicks.
//! See whp.rs; it is kept out of the build until then.

use super::Hypervisor;
use std::sync::Arc;

pub fn create() -> Result<Arc<dyn Hypervisor>, String> {
    Err("the Windows backend is being ported to paged memory (see src/hv/whp.rs)".into())
}
