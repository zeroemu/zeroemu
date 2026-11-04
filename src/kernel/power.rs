//! /sys/class/power_supply: a full battery on mains power, as the Android
//! Emulator's goldfish_battery reports by default. The health HAL reads
//! these files and aborts when the class is missing.

use crate::vfs::FileSystem;

pub fn publish(sys: &dyn FileSystem) {
    let put = |dev: &str, name: &str, value: &str| super::block::put_file(sys, &format!("class/power_supply/{dev}/{name}"), &format!("{value}\n"));
    put("ac", "type", "Mains");
    put("ac", "online", "1");
    put("ac", "uevent", "POWER_SUPPLY_NAME=ac\nPOWER_SUPPLY_TYPE=Mains\nPOWER_SUPPLY_ONLINE=1");
    for (name, value) in [
        ("type", "Battery"),
        ("status", "Full"),
        ("health", "Good"),
        ("present", "1"),
        ("capacity", "100"),
        ("technology", "Li-ion"),
        ("voltage_now", "5000000"),
        ("current_now", "900000"),
        ("charge_counter", "10000"),
        ("charge_full", "4000000"),
        ("charge_full_design", "4000000"),
        ("cycle_count", "10"),
        ("temp", "250"),
    ] {
        put("battery", name, value);
    }
    put(
        "battery",
        "uevent",
        "POWER_SUPPLY_NAME=battery\nPOWER_SUPPLY_TYPE=Battery\nPOWER_SUPPLY_STATUS=Full\nPOWER_SUPPLY_HEALTH=Good\nPOWER_SUPPLY_PRESENT=1\nPOWER_SUPPLY_CAPACITY=100",
    );
}
