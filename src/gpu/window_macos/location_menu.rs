//! Device > Location: where the device's GPS says it is (src/location.rs), chosen as
//! in Simulator's Features > Location: None, Custom Location…, then zeroemu's places,
//! then its routes, with a checkmark on the one the GPS reports. The items send
//! deviceAction: to the controls object, as the Device menu's others do, and it
//! hands them here by their tags.

use super::*;
use crate::location::{self, Kind, PRESETS, Source};

type Id = *mut c_void;

/// The items' tags, after the menu's own (TAG_HELP and on): None, Custom Location…,
/// and the presets, from TAG_PRESET by their place in PRESETS.
const TAG_OFF: i64 = 200;
const TAG_CUSTOM: i64 = 201;
const TAG_PRESET: i64 = 300;

/// Whether `tag` is one of the Location menu's items.
pub(super) fn is_tag(tag: i64) -> bool {
    tag == TAG_OFF || tag == TAG_CUSTOM || (TAG_PRESET..TAG_PRESET + PRESETS.len() as i64).contains(&tag)
}

/// The Device menu's Location item and its submenu (UI thread).
pub(super) unsafe fn item(target: Id) -> Id {
    unsafe {
        let choice = |title: &str, tag: i64| menu_item(title, "deviceAction:", "", 0, tag, target);
        let mut items = vec![choice("None", TAG_OFF), choice("Custom Location…", TAG_CUSTOM), std::ptr::null_mut()];
        let tagged = || PRESETS.iter().zip(TAG_PRESET..);
        items.extend(tagged().filter(|(p, _)| matches!(p.kind, Kind::Place { .. })).map(|(p, tag)| choice(p.name, tag)));
        items.push(std::ptr::null_mut());
        items.extend(tagged().filter(|(p, _)| matches!(p.kind, Kind::Route { .. })).map(|(p, tag)| choice(p.name, tag)));
        let menu = msg_id_ret(msg0(cls("NSMenu"), sel("alloc")), sel("initWithTitle:"), ns_str("Location"));
        for item in items {
            let item = if item.is_null() { msg0(cls("NSMenuItem"), sel("separatorItem")) } else { item };
            msg_id(menu, sel("addItem:"), item);
        }
        let top = menu_item("Location", "", "", 0, 0, std::ptr::null_mut());
        // No action of its own: it only opens the submenu.
        msg_id(top, sel("setAction:"), std::ptr::null_mut());
        msg_id(top, sel("setSubmenu:"), menu);
        top
    }
}

/// The item that stands for `source`: a point is a custom location.
fn tag_of(source: &Source) -> i64 {
    match source {
        Source::Off => TAG_OFF,
        Source::Point { .. } => TAG_CUSTOM,
        Source::Preset(id) => PRESETS.iter().position(|p| p.id == *id).map_or(0, |i| TAG_PRESET + i as i64),
    }
}

/// As a menu opens (validateMenuItem:): the checkmark on the item of what the GPS
/// reports now, whoever changed it last, the menu or the test FIFO.
pub(super) unsafe fn validate(item: Id, tag: i64) {
    // NSControlStateValueOn and Off.
    let on = tag == tag_of(&location::current());
    unsafe { msg_i64(item, sel("setState:"), on as i64) };
}

/// A Location item was chosen (UI thread).
pub(super) fn chosen(tag: i64) {
    match tag {
        TAG_OFF => location::set(Source::Off),
        TAG_CUSTOM => {
            if let Some(source) = ask_custom() {
                location::set(source);
            }
        }
        _ => {
            if let Some(p) = usize::try_from(tag - TAG_PRESET).ok().and_then(|i| PRESETS.get(i)) {
                location::set(Source::Preset(p.id));
            }
        }
    }
}

/// Custom Location…: a latitude and a longitude in one alert, as Simulator asks for
/// them, checked as device.ini's location is (Source::parse). It starts where the
/// device is, and asks again, saying why, until what is typed is a place on Earth.
/// None for Cancel.
fn ask_custom() -> Option<Source> {
    let (here, _) = location::fix();
    let (mut lat, mut lon) = here.map(|f| (format!("{:.6}", f.lat), format!("{:.6}", f.lon))).unwrap_or_default();
    let mut why = "Where the device's GPS says it is, in degrees: north and east are positive, south and west negative.";
    loop {
        (lat, lon) = unsafe { ask_two(why, &lat, &lon)? };
        if let Ok(source @ Source::Point { .. }) = Source::parse(&format!("{},{}", lat.trim(), lon.trim())) {
            return Some(source);
        }
        why = "Latitude is a number of degrees from -90 to 90, and longitude from -180 to 180, such as 37.4220 and -122.0841.";
        unsafe { NSBeep() };
    }
}

/// The alert of Custom Location…: `text`, and fields for latitude and longitude that
/// start with these. What was typed, or None for Cancel.
unsafe fn ask_two(text: &str, lat: &str, lon: &str) -> Option<(String, String)> {
    unsafe {
        let alert = msg0(list::new_alert(), sel("autorelease"));
        msg_id(alert, sel("setMessageText:"), ns_str("Custom Location"));
        msg_id(alert, sel("setInformativeText:"), ns_str(text));
        msg_id_ret(alert, sel("addButtonWithTitle:"), ns_str("OK"));
        msg_id_ret(alert, sel("addButtonWithTitle:"), ns_str("Cancel"));
        let field = |value: &str, example: &str| {
            let f = msg_id_ret(cls("NSTextField"), sel("textFieldWithString:"), ns_str(value));
            msg_id(f, sel("setPlaceholderString:"), ns_str(example));
            let width = msg_f64_id(msg0(f, sel("widthAnchor")), sel("constraintEqualToConstant:"), 200.0);
            msg_bool(width, sel("setActive:"), 1);
            f
        };
        let (lat_field, lon_field) = (field(lat, "37.4220"), field(lon, "-122.0841"));
        msg_id(lat_field, sel("setNextKeyView:"), lon_field);
        msg_id(lon_field, sel("setNextKeyView:"), lat_field);
        let label = |text: &str| msg_id_ret(cls("NSTextField"), sel("labelWithString:"), ns_str(text));
        // Two rows of a label and its field, the labels lined up at their ends, as the
        // New Device form's (list.rs, set_accessory).
        let rows = [ns_array(&[label("Latitude:"), lat_field]), ns_array(&[label("Longitude:"), lon_field])];
        let grid = msg_id_ret(cls("NSGridView"), sel("gridViewWithViews:"), ns_array(&rows));
        let set_f64: unsafe extern "C" fn(Id, Id, f64) = std::mem::transmute(objc_msgSend as *const ());
        set_f64(grid, sel("setRowSpacing:"), 10.0);
        set_f64(grid, sel("setColumnSpacing:"), 8.0);
        msg_i64(msg_i64_id_ret(grid, sel("columnAtIndex:"), 0), sel("setXPlacement:"), 3); // trailing
        msg_i64(grid, sel("setRowAlignment:"), 2); // first baselines
        let fitting: unsafe extern "C" fn(Id, Id) -> NSSize = std::mem::transmute(objc_msgSend as *const ());
        msg_size(grid, sel("setFrameSize:"), fitting(grid, sel("fittingSize")));
        msg_id(alert, sel("setAccessoryView:"), grid);
        msg_void(alert, sel("layout"));
        msg_id(msg0(alert, sel("window")), sel("setInitialFirstResponder:"), lat_field);
        // NSAlertFirstButtonReturn, OK.
        (msg_i64_ret(alert, sel("runModal")) == 1000).then(|| (rust_str(msg0(lat_field, sel("stringValue"))), rust_str(msg0(lon_field, sel("stringValue")))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_source_checks_one_item() {
        assert_eq!(tag_of(&Source::Off), TAG_OFF);
        assert_eq!(tag_of(&Source::Point { lat: 1.0, lon: 2.0 }), TAG_CUSTOM);
        let tags: Vec<i64> = PRESETS.iter().map(|p| tag_of(&Source::Preset(p.id))).collect();
        assert!(tags.iter().all(|&t| is_tag(t) && t >= TAG_PRESET));
        assert!(tags.windows(2).all(|w| w[0] < w[1]), "one each");
        assert!(!is_tag(TAG_PRESET + PRESETS.len() as i64) && !is_tag(TAG_LIST) && !is_tag(0));
        // Clear of the device's own actions' tags.
        assert!(Action::ALL.iter().all(|a| !is_tag(a.tag())));
    }
}
