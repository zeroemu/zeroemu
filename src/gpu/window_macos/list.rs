//! zeroemu.app's list of devices (src/devices.rs), which it shows when it is opened
//! with nothing to do: make a device from an installed system image, start one, and
//! rename, wipe or delete one. Starting one ends the list, and this process boots it:
//! a process runs one device, as Hypervisor.framework gives it one VM. AppKit through
//! the same raw messages as the device's window (super).

use super::*;
use crate::devices::{self, Device, Settings, Store};
use crate::gpu::Display;
use crate::location::{self, Source};
use crate::sdk::{self, Image, Support};
use std::cell::RefCell;
use std::path::PathBuf;

type Id = *mut c_void;

/// What the list shows, kept on the UI thread.
struct List {
    window: Id,
    table: Id,
    scroll: Id,
    empty: Id,
    store: Store,
    images: Vec<Image>,
    /// Whether each image can boot, worked out the first time the form wants it:
    /// that reads every image's partitions.
    supports: Option<Vec<Support>>,
    devices: Vec<Device>,
    running: Vec<Option<Option<u32>>>,
}

/// The form making a device: its fields, and the name it suggested, which a change of
/// image replaces until the name is typed over.
struct Form {
    field: Id,
    /// The image popup; null when editing, as a device keeps its image.
    popup: Id,
    suggested: String,
    settings: SettingsRows,
    /// Advanced Settings is open.
    advanced: bool,
}

/// What runModal returns when Advanced Settings is opened or closed: the form shows
/// again at its new size, as an alert can't change size while it shows.
const TOGGLE_ADVANCED: i64 = 1100;

thread_local! {
    /// Whether the form, shown again, has Advanced Settings open.
    static ADVANCED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static LIST: RefCell<Option<List>> = const { RefCell::new(None) };
    static FORM: RefCell<Option<Form>> = const { RefCell::new(None) };
}

/// The list is done with: a device to boot, or None to quit.
static DONE: AtomicBool = AtomicBool::new(false);
static CHOSEN: Mutex<Option<String>> = Mutex::new(None);

/// `f` with the list, if there is one. Not across an alert or a menu: those run
/// events, which may want the list too.
fn with_list<R>(f: impl FnOnce(&mut List) -> R) -> Option<R> {
    LIST.with(|l| l.borrow_mut().as_mut().map(f))
}

/// The list's window until a device is chosen, which this returns, or None when the
/// window is closed or zeroemu quit, or another zeroemu shows the list already, which
/// this brings forward instead: one list at a time (app::hold_list).
pub fn choose() -> Option<String> {
    // Held while the list shows: let go when this returns, before a chosen device boots.
    let _shown = match crate::app::hold_list() {
        Ok(lock) => lock,
        Err(pid) => {
            if let Some(pid) = pid {
                super::activate_pid(pid);
            }
            return None;
        }
    };
    let Some(store) = Store::open() else {
        super::alert("zeroemu can't keep devices", "HOME isn't set, so there's nowhere to keep them.", false);
        return None;
    };
    let images = installed_images();
    store.adopt(&images, |i| crate::default_data_image(&i.system_img()));
    let show = !background();
    let mut timer = std::ptr::null_mut();
    with_pool(|| unsafe {
        let app = msg0(cls("NSApplication"), sel("sharedApplication"));
        msg_i64(app, sel("setActivationPolicy:"), 0);
        set_app_icon(app);
        APP.store(app, Ordering::Release);
        msg_id(app, sel("setDelegate:"), list_object());
        set_up_list_menus(app);
        build(store, images);
        let window = with_list(|l| l.window).unwrap_or(std::ptr::null_mut());
        if show {
            msg_id(window, sel("makeKeyAndOrderFront:"), std::ptr::null_mut());
            msg_bool(app, sel("activateIgnoringOtherApps:"), 1);
        } else {
            msg_id(window, sel("orderBack:"), std::ptr::null_mut());
        }
        finish_launching(app);
        // Running devices change in other zeroemus: looked at every two seconds.
        let f: unsafe extern "C" fn(Id, Id, f64, Id, Id, Id, i8) -> Id = std::mem::transmute(objc_msgSend as *const ());
        timer = f(cls("NSTimer"), sel("scheduledTimerWithTimeInterval:target:selector:userInfo:repeats:"), 2.0, list_object(), sel("tick:"), std::ptr::null_mut(), 1);
        // Nothing to start: the form at once, once the window is up. Not for a test
        // working the list from its FIFO, which the form would hold up.
        let fifo = std::env::var_os("ZEROEMU_LIST_FIFO").is_some();
        if show && !fifo && with_list(|l| l.devices.is_empty()).unwrap_or(false) {
            let f: unsafe extern "C" fn(Id, Id, Id, Id, f64) = std::mem::transmute(objc_msgSend as *const ());
            f(list_object(), sel("performSelector:withObject:afterDelay:"), sel("newDevice:"), std::ptr::null_mut(), 0.3);
        }
    });
    start_fifo();
    while !DONE.load(Ordering::Acquire) {
        with_pool(|| unsafe {
            let app = APP.load(Ordering::Acquire);
            let until = msg_f64_id(cls("NSDate"), sel("dateWithTimeIntervalSinceNow:"), 0.25);
            let event = msg_next_event(app, sel("nextEventMatchingMask:untilDate:inMode:dequeue:"), u64::MAX, until, NSDefaultRunLoopMode, 1);
            if !event.is_null() {
                msg_id(app, sel("sendEvent:"), event);
                msg_void(app, sel("updateWindows"));
            }
        });
    }
    let chosen = CHOSEN.lock().unwrap().take();
    // Nothing of the list may act once a device runs in this process: its timer, a
    // New Device still pending, its table's calls, its FIFO reader.
    with_pool(|| unsafe {
        msg_void(timer, sel("invalidate"));
        msg_id(cls("NSObject"), sel("cancelPreviousPerformRequestsWithTarget:"), list_object());
        if let Some((window, table)) = with_list(|l| (l.window, l.table)) {
            msg_id(table, sel("setDataSource:"), std::ptr::null_mut());
            msg_id(table, sel("setDelegate:"), std::ptr::null_mut());
            msg_id(window, sel("setDelegate:"), std::ptr::null_mut());
            msg_id(window, sel("orderOut:"), std::ptr::null_mut());
        }
    });
    LIST.with(|l| l.borrow_mut().take());
    stop_fifo();
    chosen
}

/// The SDK's images now: the list looks again whenever it shows, as the way to get one
/// it gives is to install it.
fn installed_images() -> Vec<Image> {
    sdk::find().filter(|s| s.exists()).map(|s| s.images()).unwrap_or_default()
}

/// ZEROEMU_LIST_SNAPSHOT=<dir>: draws the list and the form making a device, light and
/// dark, into list-light.png, new-device-dark.png and so on there, without showing
/// either: for tests, and for looking at their layout without a screen.
pub fn snapshot(dir: &std::path::Path) -> Result<(), String> {
    let store = Store::open().ok_or("HOME isn't set")?;
    let images = installed_images();
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    with_pool(|| unsafe {
        let app = msg0(cls("NSApplication"), sel("sharedApplication"));
        msg_i64(app, sel("setActivationPolicy:"), 2); // prohibited: no Dock icon
        set_app_icon(app);
        build(store, images);
        let (window, table) = with_list(|l| (l.window, l.table)).unwrap();
        let (alert, _) = form_alert(None, false)?;
        let sheet = msg0(alert, sel("window"));
        let (open, _) = form_alert(None, true)?;
        let open_sheet = msg0(open, sel("window"));
        for (look, name) in [("light", "NSAppearanceNameAqua"), ("dark", "NSAppearanceNameDarkAqua")] {
            let appearance = msg_id_ret(cls("NSAppearance"), sel("appearanceNamed:"), ns_str(name));
            for w in [window, sheet, open_sheet] {
                msg_id(w, sel("setAppearance:"), appearance);
            }
            let content = msg0(window, sel("contentView"));
            msg_void(content, sel("layoutSubtreeIfNeeded"));
            msg_void(table, sel("reloadData"));
            msg_void(content, sel("layoutSubtreeIfNeeded"));
            draw_view(content, appearance, &dir.join(format!("list-{look}.png")))?;
            msg_void(alert, sel("layout"));
            draw_view(msg0(sheet, sel("contentView")), appearance, &dir.join(format!("new-device-{look}.png")))?;
            msg_void(open, sel("layout"));
            draw_view(msg0(open_sheet, sel("contentView")), appearance, &dir.join(format!("new-device-advanced-{look}.png")))?;
        }
        Ok(())
    })
}

#[link(name = "AppKit", kind = "framework")]
unsafe extern "C" {
    fn NSRectFill(rect: NSRect);
}

/// `view` on its window's background, as a PNG.
unsafe fn draw_view(view: Id, appearance: Id, path: &std::path::Path) -> Result<(), String> {
    unsafe {
        let bounds = msg_rect(view, sel("bounds"));
        let f: unsafe extern "C" fn(Id, Id, NSRect) -> Id = std::mem::transmute(objc_msgSend as *const ());
        let rep = f(view, sel("bitmapImageRepForCachingDisplayInRect:"), bounds);
        if rep.is_null() {
            return Err(format!("{}: nothing to draw", path.display()));
        }
        let context = msg_id_ret(cls("NSGraphicsContext"), sel("graphicsContextWithBitmapImageRep:"), rep);
        msg_void(cls("NSGraphicsContext"), sel("saveGraphicsState"));
        msg_id(cls("NSGraphicsContext"), sel("setCurrentContext:"), context);
        let previous = msg0(cls("NSAppearance"), sel("currentAppearance"));
        msg_id(cls("NSAppearance"), sel("setCurrentAppearance:"), appearance);
        msg_void(msg0(cls("NSColor"), sel("windowBackgroundColor")), sel("setFill"));
        NSRectFill(bounds);
        let g: unsafe extern "C" fn(Id, Id, NSRect, Id) = std::mem::transmute(objc_msgSend as *const ());
        g(view, sel("displayRectIgnoringOpacity:inContext:"), bounds, context);
        msg_id(cls("NSAppearance"), sel("setCurrentAppearance:"), previous);
        msg_void(cls("NSGraphicsContext"), sel("restoreGraphicsState"));
        // NSBitmapImageFileTypePNG.
        let h: unsafe extern "C" fn(Id, Id, u64, Id) -> Id = std::mem::transmute(objc_msgSend as *const ());
        let data = h(rep, sel("representationUsingType:properties:"), 4, msg0(cls("NSDictionary"), sel("dictionary")));
        let png = std::slice::from_raw_parts(msg0(data, sel("bytes")) as *const u8, msg_i64_ret(data, sel("length")) as usize);
        std::fs::write(path, png).map_err(|e| format!("{}: {e}", path.display()))
    }
}

// ---- Building the window ----

/// The window and what it shows, unshown (UI thread).
unsafe fn build(store: Store, images: Vec<Image>) {
    unsafe {
        let rect = NSRect { origin: NSPoint { x: 0.0, y: 0.0 }, size: NSSize { width: 560.0, height: 420.0 } };
        // titled | closable | miniaturizable | resizable, buffered, don't defer.
        let window = msg_init_window(msg0(cls("NSWindow"), sel("alloc")), sel("initWithContentRect:styleMask:backing:defer:"), rect, 15, 2, 0);
        msg_id(window, sel("setTitle:"), ns_str("zeroemu"));
        msg_bool(window, sel("setReleasedWhenClosed:"), 0);
        msg_bool(cls("NSWindow"), sel("setAllowsAutomaticWindowTabbing:"), 0);
        msg_size(window, sel("setContentMinSize:"), NSSize { width: 440.0, height: 300.0 });
        msg_void(window, sel("center"));
        msg_id_bool_ret(window, sel("setFrameAutosaveName:"), ns_str("zeroemu.devices"));
        msg_id(window, sel("setDelegate:"), list_object());
        let content = msg0(window, sel("contentView"));

        let title = label("Devices");
        msg_id(title, sel("setFont:"), font(20.0, WEIGHT_SEMIBOLD));
        let new = button("New Device…", "newDevice:", 0);
        msg_id(new, sel("setImage:"), symbol("plus", 12.0));
        msg_i64(new, sel("setImagePosition:"), IMAGE_LEADING);
        let header = row_stack(&[title, new], 12.0);
        hug(title, 1.0);
        add(content, header);
        pin(header, "topAnchor", content, "topAnchor", 16.0);
        pin(header, "leadingAnchor", content, "leadingAnchor", 20.0);
        pin(header, "trailingAnchor", content, "trailingAnchor", -20.0);

        let table = msg0(msg0(cls("NSTableView"), sel("alloc")), sel("init"));
        msg_i64(table, sel("setStyle:"), 2); // inset: rows away from the edges, rounded
        msg_id(table, sel("setHeaderView:"), std::ptr::null_mut());
        msg_f64(table, sel("setRowHeight:"), 56.0);
        msg_i64(table, sel("setColumnAutoresizingStyle:"), 1); // the one column fills it
        let column = msg_id_ret(msg0(cls("NSTableColumn"), sel("alloc")), sel("initWithIdentifier:"), ns_str("device"));
        msg_id(table, sel("addTableColumn:"), column);
        msg_id(table, sel("setDataSource:"), list_object());
        msg_id(table, sel("setDelegate:"), list_object());
        msg_id(table, sel("setTarget:"), list_object());
        msg_id(table, sel("setDoubleAction:"), sel("startClicked:"));
        let context = msg_id_ret(msg0(cls("NSMenu"), sel("alloc")), sel("initWithTitle:"), ns_str("Device"));
        msg_id(context, sel("setDelegate:"), list_object());
        msg_id(table, sel("setMenu:"), context);
        let scroll = msg0(msg0(cls("NSScrollView"), sel("alloc")), sel("init"));
        msg_id(scroll, sel("setDocumentView:"), table);
        msg_bool(scroll, sel("setHasVerticalScroller:"), 1);
        msg_bool(scroll, sel("setAutohidesScrollers:"), 1);
        msg_bool(scroll, sel("setDrawsBackground:"), 0);
        add(content, scroll);
        pin(scroll, "topAnchor", header, "bottomAnchor", 8.0);
        pin(scroll, "leadingAnchor", content, "leadingAnchor", 10.0);
        pin(scroll, "trailingAnchor", content, "trailingAnchor", -10.0);
        pin(scroll, "bottomAnchor", content, "bottomAnchor", -12.0);

        // No devices: what they are, and the way to make one.
        let icon = image_view(symbol("iphone.gen3", 44.0), "tertiaryLabelColor");
        let none = label("No Devices");
        msg_id(none, sel("setFont:"), font(17.0, WEIGHT_SEMIBOLD));
        let what = wrapping_label("A device runs a system image from your Android SDK, with its own apps and data.");
        msg_i64(what, sel("setAlignment:"), 1); // centered (NSTextAlignmentCenter on Apple silicon)
        let make = button("New Device…", "newDevice:", 0);
        let empty = column_stack(&[icon, none, what, make], 10.0, ALIGN_CENTER_X);
        add(content, empty);
        pin(empty, "centerXAnchor", scroll, "centerXAnchor", 0.0);
        pin(empty, "centerYAnchor", scroll, "centerYAnchor", -10.0);
        pin_const(what, "widthAnchor", 320.0);

        LIST.with(|l| {
            *l.borrow_mut() = Some(List { window, table, scroll, empty, store, images, supports: None, devices: Vec::new(), running: Vec::new() })
        });
        refresh(None);
    }
}

/// Reads the devices again and shows them, keeping `select` (an id) or the selected
/// device selected.
fn refresh(select: Option<&str>) {
    let Some(table) = with_list(|l| l.table) else { return };
    // AppKit calls back into the list (rows, view_for_row) from what these do, so
    // never while it is borrowed.
    let selected = unsafe { msg_i64_ret(table, sel("selectedRow")) };
    let images = installed_images();
    let Some((row, none, scroll, empty)) = with_list(|l| {
        let keep = select.map(str::to_string).or_else(|| usize::try_from(selected).ok().and_then(|i| l.devices.get(i)).map(|d| d.id.clone()));
        if images.iter().map(Image::package).ne(l.images.iter().map(Image::package)) {
            l.supports = None;
        }
        l.images = images;
        // What a terminal boot saved since, as a device too.
        l.store.adopt(&l.images, |i| crate::default_data_image(&i.system_img()));
        l.devices = l.store.list();
        l.running = l.devices.iter().map(Device::running).collect();
        let row = keep.and_then(|id| l.devices.iter().position(|d| d.id == id));
        (row, l.devices.is_empty(), l.scroll, l.empty)
    }) else {
        return;
    };
    unsafe {
        msg_void(table, sel("reloadData"));
        if let Some(row) = row {
            let set = msg_i64_id_ret(cls("NSIndexSet"), sel("indexSetWithIndex:"), row as i64);
            let f: unsafe extern "C" fn(Id, Id, Id, i8) = std::mem::transmute(objc_msgSend as *const ());
            f(table, sel("selectRowIndexes:byExtendingSelection:"), set, 0);
        }
        msg_bool(scroll, sel("setHidden:"), none as i8);
        msg_bool(empty, sel("setHidden:"), (!none) as i8);
    }
}

/// One device's row: its name, its image and whether it runs, Start (or Show, for one
/// running in another zeroemu) and a menu of the rest.
unsafe fn device_row(row: i64, d: &Device, shown: &str, running: bool, installed: bool) -> Id {
    unsafe {
        let cell = msg0(msg0(cls("NSTableCellView"), sel("alloc")), sel("init"));
        let icon = image_view(symbol("iphone.gen3", 22.0), "secondaryLabelColor");
        let name = label(&d.name);
        msg_id(name, sel("setFont:"), font(13.0, WEIGHT_SEMIBOLD));
        let detail = label(&if running { format!("{shown} · Running") } else { shown.to_string() });
        msg_id(detail, sel("setFont:"), font(11.0, 0.0));
        msg_id(detail, sel("setTextColor:"), msg0(cls("NSColor"), sel("secondaryLabelColor")));
        for l in [name, detail] {
            msg_i64(l, sel("setLineBreakMode:"), 4); // …at the end
            squeeze(l);
        }
        let texts = column_stack(&[name, detail], 2.0, ALIGN_LEADING);
        hug(texts, 1.0);
        squeeze(texts);
        let start = button(if running { "Show" } else { "Start" }, "startDevice:", row);
        msg_id(start, sel("setImage:"), symbol(if running { "macwindow" } else { "play.fill" }, 11.0));
        msg_i64(start, sel("setImagePosition:"), IMAGE_LEADING);
        msg_bool(start, sel("setEnabled:"), (running || installed) as i8);
        if !installed {
            msg_id(start, sel("setToolTip:"), ns_str("Its system image isn't installed"));
        }
        let more = msg_id_id_ret_sel(cls("NSButton"), sel("buttonWithImage:target:action:"), symbol("ellipsis.circle", 15.0), list_object(), sel("deviceMenu:"));
        msg_bool(more, sel("setBordered:"), 0);
        msg_i64(more, sel("setTag:"), row);
        msg_id(more, sel("setToolTip:"), ns_str("More"));
        let line = row_stack(&[icon, texts, start, more], 12.0);
        add(cell, line);
        pin(line, "leadingAnchor", cell, "leadingAnchor", 8.0);
        pin(line, "trailingAnchor", cell, "trailingAnchor", -6.0);
        pin(line, "centerYAnchor", cell, "centerYAnchor", 0.0);
        msg0(cell, sel("autorelease"))
    }
}

// ---- The object AppKit calls ----

static LIST_OBJECT: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

/// The list's target, data source, delegate and the application's delegate, made once
/// (UI thread). Never let go: AppKit holds it weakly.
fn list_object() -> Id {
    let have = LIST_OBJECT.load(Ordering::Acquire);
    if !have.is_null() {
        return have;
    }
    unsafe {
        let name = CString::new("ZeroemuDeviceList").unwrap();
        let class = objc_allocateClassPair(cls("NSObject"), name.as_ptr(), 0);
        if class.is_null() {
            return std::ptr::null_mut();
        }
        let action = "v24@0:8@16";
        let methods: [(&str, *const c_void, &str); 21] = [
            ("numberOfRowsInTableView:", rows as *const c_void, "q24@0:8@16"),
            ("tableView:viewForTableColumn:row:", view_for_row as *const c_void, "@40@0:8@16@24q32"),
            ("startDevice:", start_device as *const c_void, action),
            ("startClicked:", start_clicked as *const c_void, action),
            ("newDevice:", new_device as *const c_void, action),
            ("deviceMenu:", device_menu as *const c_void, action),
            ("editDevice:", edit_device as *const c_void, action),
            ("presetChosen:", preset_chosen as *const c_void, action),
            ("advancedToggled:", advanced_toggled as *const c_void, action),
            ("locationChosen:", location_chosen as *const c_void, action),
            ("controlTextDidChange:", screen_typed as *const c_void, action),
            ("comboBoxSelectionDidChange:", density_picked as *const c_void, action),
            ("wipeDevice:", wipe_device as *const c_void, action),
            ("revealDevice:", reveal_device as *const c_void, action),
            ("deleteDevice:", delete_device as *const c_void, action),
            ("imageChosen:", image_chosen as *const c_void, action),
            ("menuNeedsUpdate:", menu_needs_update as *const c_void, action),
            ("windowWillClose:", window_will_close as *const c_void, action),
            ("windowDidBecomeKey:", became_key as *const c_void, action),
            ("applicationDidBecomeActive:", became_active as *const c_void, action),
            ("tick:", tick as *const c_void, action),
        ];
        for (selector, imp, types) in methods {
            let types = CString::new(types).unwrap();
            class_addMethod(class, sel(selector), imp, types.as_ptr());
        }
        objc_registerClassPair(class);
        let obj = msg0(msg0(class, sel("alloc")), sel("init"));
        LIST_OBJECT.store(obj, Ordering::Release);
        obj
    }
}

extern "C" fn rows(_this: Id, _cmd: Id, _table: Id) -> i64 {
    with_list(|l| l.devices.len() as i64).unwrap_or(0)
}

extern "C" fn view_for_row(_this: Id, _cmd: Id, _table: Id, _column: Id, row: i64) -> Id {
    let Some((d, shown, running, installed)) = with_list(|l| {
        let i = usize::try_from(row).ok()?;
        let d = l.devices.get(i)?.clone();
        let running = l.running.get(i).is_some_and(Option::is_some);
        Some((d.image_shown(&l.images), running, d.image(&l.images).is_some(), d)).map(|(shown, running, installed, d)| (d, shown, running, installed))
    })
    .flatten() else {
        return std::ptr::null_mut();
    };
    unsafe { device_row(row, &d, &shown, running, installed) }
}

/// The device in `row`, and its process id if it is running in some zeroemu.
fn device_at(row: i64) -> Option<(Device, Option<Option<u32>>)> {
    with_list(|l| {
        let i = usize::try_from(row).ok()?;
        Some((l.devices.get(i)?.clone(), l.running.get(i).copied().flatten()))
    })
    .flatten()
}

extern "C" fn start_device(_this: Id, _cmd: Id, sender: Id) {
    start(unsafe { msg_i64_ret(sender, sel("tag")) });
}

/// A double click (the table's double action): the clicked row's. Start in a row's
/// menu is startDevice:, its tag the row.
extern "C" fn start_clicked(_this: Id, _cmd: Id, _sender: Id) {
    if let Some(row) = with_list(|l| unsafe { msg_i64_ret(l.table, sel("clickedRow")) }) {
        start(row);
    }
}

/// Starts the device in `row` here, or brings forward the zeroemu running it.
fn start(row: i64) {
    let Some((d, running)) = device_at(row) else { return };
    // Running already, perhaps since the list last looked.
    let running = running.or_else(|| d.running());
    if let Some(pid) = running {
        if let Some(pid) = pid {
            super::activate_pid(pid);
        }
        return;
    }
    let installed = with_list(|l| d.image(&l.images).is_some()).unwrap_or(false);
    if !installed {
        let fix = sdk::find().map(|s| s.sdkmanager(&d.package)).unwrap_or_default();
        show_alert(&format!("{}'s system image isn't installed", d.name), &format!("{}\n\nInstall it with:\n{fix}", d.package), &["OK"]);
        return;
    }
    choose_device(d.id);
}

fn choose_device(id: String) {
    // By id, which `--device` takes as such: a name may be another device's id.
    *CHOSEN.lock().unwrap() = Some(format!("id:{id}"));
    DONE.store(true, Ordering::Release);
}

extern "C" fn new_device(_this: Id, _cmd: Id, _sender: Id) {
    refresh(None);
    let Some(have_images) = with_list(|l| {
        l.supports = None;
        !l.images.is_empty()
    }) else { return };
    if !have_images {
        let (title, text, command) = match sdk::require() {
            Err(p) => ("There's no Android SDK".to_string(), p.to_string(), None),
            Ok(s) => {
                let command = s.sdkmanager(&sdk::tested_package());
                ("No system images are installed".to_string(), format!("Install the one zeroemu is tested with, then make a device again:\n\n{command}"), Some(command))
            }
        };
        let buttons: &[&str] = if command.is_some() { &["Copy Command", "OK"] } else { &["OK"] };
        if show_alert(&title, &text, buttons) == 0
            && let Some(c) = command
        {
            copy_text(&c);
        }
        return;
    }
    // The image by its folder, not its place in the popup: the list may be scanned again
    // before the form is shown again (refresh, as the list window becomes key once the
    // form orders out), and an image installed or removed meanwhile moves the others.
    let mut entered: Option<(String, Option<PathBuf>, Raw)> = None;
    ADVANCED.with(|a| a.set(false));
    loop {
        let Ok((alert, form)) = (unsafe { form_alert(entered.as_ref(), ADVANCED.with(|a| a.get())) }) else { return };
        let creates = form.is_some();
        FORM.with(|f| *f.borrow_mut() = form);
        let answer = unsafe { msg_i64_ret(alert, sel("runModal")) };
        let Some(form) = FORM.with(|f| f.borrow_mut().take()) else {
            // None of them can start: the form showed them, why, and what to install.
            if !creates
                && answer == 1000
                && let Some(c) = install_command()
            {
                copy_text(&c);
            }
            return;
        };
        let name = unsafe { rust_str(msg0(form.field, sel("stringValue"))) };
        let index = unsafe { msg_i64_ret(form.popup, sel("indexOfSelectedItem")) }.max(0) as usize;
        let raw = unsafe { form.settings.read() };
        let image = with_list(|l| l.images.get(index).map(|i| i.dir.clone())).flatten();
        if answer == TOGGLE_ADVANCED {
            unsafe { msg_id(msg0(alert, sel("window")), sel("orderOut:"), std::ptr::null_mut()) };
            entered = Some((name, image, raw));
            continue;
        }
        if answer != 1000 {
            return;
        }
        let made = raw.to_settings(&Settings::default()).and_then(|settings| {
            with_list(|l| match (l.images.get(index), l.supports.as_ref().and_then(|s| s.get(index))) {
                (Some(img), Some(support)) if support.boots() => l.store.create_with(&name, img, &settings),
                _ => Err("choose a system image that can start".into()),
            })
            .ok_or_else(String::new)?
        });
        match made {
            Ok(d) => return refresh(Some(&d.id)),
            Err(e) if e.is_empty() => return,
            Err(e) => {
                show_alert("The device wasn't made", &e, &["OK"]);
                entered = Some((name, image, raw));
            }
        }
    }
}

/// The form making a device, as an alert with Create and Cancel: a name, and the
/// installed images, those that can't boot shown but not chosen. `entered` is what
/// was typed and chosen before, when that was refused. When none of the images can
/// boot, no Form: the images all shown but not chosen, why the one shown can't boot,
/// and what to install, with Copy Command (if there's an SDK to say it for) and OK.
unsafe fn form_alert(entered: Option<&(String, Option<PathBuf>, Raw)>, advanced: bool) -> Result<(Id, Option<Form>), String> {
    let (images, supports, devices) = with_list(|l| {
        let supports = l.supports.get_or_insert_with(|| l.images.iter().map(sdk::classify).collect()).clone();
        (l.images.clone(), supports, l.devices.clone())
    })
    .ok_or("no list")?;
    let first = default_image(&supports);
    // No images at all is said before the form (new_device); drawn (snapshot), the form.
    let creates = first.is_some() || images.is_empty();
    unsafe {
        let alert = msg0(new_alert(), sel("autorelease"));
        if creates {
            msg_id(alert, sel("setMessageText:"), ns_str("New Device"));
            msg_id(alert, sel("setInformativeText:"), ns_str("A device runs one system image from your Android SDK and keeps its own apps and data."));
            msg_id_ret(alert, sel("addButtonWithTitle:"), ns_str("Create"));
            msg_id_ret(alert, sel("addButtonWithTitle:"), ns_str("Cancel"));
        } else {
            let command = install_command();
            let tested_why = images.iter().zip(&supports).find(|(i, _)| i.package() == sdk::tested_package()).and_then(|(_, s)| match s {
                Support::Unsupported(why) => Some(why.as_str()),
                _ => None,
            });
            msg_id(alert, sel("setMessageText:"), ns_str("None of your system images can start"));
            msg_id(alert, sel("setInformativeText:"), ns_str(&cant_start_text(tested_why, command.as_deref())));
            if command.is_some() {
                msg_id_ret(alert, sel("addButtonWithTitle:"), ns_str("Copy Command"));
            }
            msg_id_ret(alert, sel("addButtonWithTitle:"), ns_str("OK"));
        }

        let popup = msg_init_popup(msg0(cls("NSPopUpButton"), sel("alloc")), sel("initWithFrame:pullsDown:"), NSRect { origin: NSPoint { x: 0.0, y: 0.0 }, size: NSSize { width: 280.0, height: 26.0 } }, 0);
        msg_bool(popup, sel("setAutoenablesItems:"), 0);
        // Into its menu, not with addItemWithTitle:, which drops an item of the same
        // title: each item's place must be its image's in `images`.
        let menu = msg0(popup, sel("menu"));
        for (title, (img, support)) in image_titles(&images).into_iter().zip(images.iter().zip(&supports)) {
            let title = match support {
                Support::Tested => format!("{title} (tested)"),
                Support::Untested => title,
                Support::Unsupported(_) => format!("{title} (can't boot)"),
            };
            let item = menu_item(&title, "", "", 0, 0, std::ptr::null_mut());
            msg_id(item, sel("setAction:"), std::ptr::null_mut());
            msg_id(menu, sel("addItem:"), item);
            msg_void(item, sel("release"));
            msg_id(item, sel("setToolTip:"), ns_str(&format!("{} ({})", img.name(), match support {
                Support::Unsupported(why) => why.clone(),
                other => other.to_string(),
            })));
            msg_bool(item, sel("setEnabled:"), support.boots() as i8);
        }
        // None boots: the tested image shown, as the text speaks of it, else the first.
        let tested = || images.iter().position(|i| i.package() == sdk::tested_package());
        // The one chosen before, if it is still there.
        let before = entered.and_then(|e| e.1.as_ref()).and_then(|dir| images.iter().position(|i| &i.dir == dir));
        let chosen = before.or(first).or_else(tested).unwrap_or(0);
        msg_i64(popup, sel("selectItemAtIndex:"), chosen as i64);
        msg0(popup, sel("autorelease"));
        pin_const(popup, "widthAnchor", 280.0);
        let note = |text: &str| {
            let note = wrapping_label(text);
            msg_id(note, sel("setFont:"), font(11.0, 0.0));
            pin_const(note, "widthAnchor", 280.0);
            [msg0(cls("NSGridCell"), sel("emptyContentView")), note]
        };
        if !creates {
            // Nothing to name or create: the images, and why the one shown can't boot.
            let mut rows = vec![[label(if images.len() == 1 { "Installed image:" } else { "Installed images:" }), popup]];
            if let Some(Support::Unsupported(why)) = supports.get(chosen) {
                rows.push(note(&format!("Can't boot: {why}.")));
            }
            set_accessory(alert, &rows);
            return Ok((alert, None));
        }
        msg_id(popup, sel("setTarget:"), list_object());
        msg_id(popup, sel("setAction:"), sel("imageChosen:"));

        let suggested = images.get(chosen).map(|i| devices::default_name(i, &devices)).unwrap_or_default();
        let field = msg_id_ret(cls("NSTextField"), sel("textFieldWithString:"), ns_str(entered.map_or(&suggested, |e| &e.0)));
        pin_const(field, "widthAnchor", 280.0);

        let mut rows = vec![[label("Name:"), field], [label("System image:"), popup]];
        if supports.contains(&Support::Untested) {
            rows.push(note("zeroemu is tested with one image; others may not start all the way."));
        }
        let raw = entered.map(|e| e.2.clone()).unwrap_or_else(|| Raw::from_settings(&Settings::default()));
        let (settings, more, hidden) = SettingsRows::new(&raw, advanced);
        rows.extend(more);
        set_accessory_hiding(alert, &rows, hidden);
        msg_id(msg0(alert, sel("window")), sel("setInitialFirstResponder:"), field);
        Ok((alert, Some(Form { field, popup, suggested, settings, advanced })))
    }
}

/// The form's rows, a label and its control each, under the alert's text.
unsafe fn set_accessory(alert: Id, rows: &[[Id; 2]]) {
    unsafe { set_accessory_hiding(alert, rows, 0) }
}

/// The form's rows, the last `hidden` of them there but not shown (Advanced Settings,
/// closed): their controls still hold the values.
unsafe fn set_accessory_hiding(alert: Id, rows: &[[Id; 2]], hidden: usize) {
    unsafe {
        let count = rows.len();
        let rows: Vec<Id> = rows.iter().map(|r| ns_array(r)).collect();
        let grid = msg_id_ret(cls("NSGridView"), sel("gridViewWithViews:"), ns_array(&rows));
        for i in count.saturating_sub(hidden)..count {
            msg_bool(msg_i64_id_ret(grid, sel("rowAtIndex:"), i as i64), sel("setHidden:"), 1);
        }
        msg_f64(grid, sel("setRowSpacing:"), 10.0);
        msg_f64(grid, sel("setColumnSpacing:"), 8.0);
        msg_i64(msg_i64_id_ret(grid, sel("columnAtIndex:"), 0), sel("setXPlacement:"), 3); // trailing
        msg_i64(grid, sel("setRowAlignment:"), 2); // first baselines
        let fit = msg_size_ret(grid, sel("fittingSize"));
        msg_size(grid, sel("setFrameSize:"), fit);
        msg_id(alert, sel("setAccessoryView:"), grid);
        msg_void(alert, sel("layout"));
    }
}

/// The image the form chooses first: the tested one, or else the first that boots.
/// None when none of them boots, when there's nothing to create.
fn default_image(supports: &[Support]) -> Option<usize> {
    supports.iter().position(|s| *s == Support::Tested).or_else(|| supports.iter().position(Support::boots))
}

/// The SDK's command installing the tested image, when there's an SDK.
fn install_command() -> Option<String> {
    sdk::find().filter(|s| s.exists()).map(|s| s.sdkmanager(&sdk::tested_package()))
}

/// What the form says when images are installed but none of them can boot: what to
/// install, and why the tested image can't if it is one of them (then it is to be
/// installed again). `command` installs it.
fn cant_start_text(tested_why: Option<&str>, command: Option<&str>) -> String {
    let mut text = match tested_why {
        Some(why) => format!(
            "The image zeroemu is tested with is installed but can't start ({why}). Remove it in SDK Manager, then install it again and make a device"
        ),
        None => "Those installed are listed below, with why the one shown can't start. Install the image zeroemu is tested with, then make a device".to_string(),
    };
    match command {
        Some(c) => text += &format!(":\n\n{c}"),
        None => text += &format!(": {}.", sdk::tested_package()),
    }
    text
}

/// What the form calls each image: its Android version and kind, with its level, then
/// its ABI, where two would otherwise read the same (android-36 and android-36.1 are
/// both Android 16).
fn image_titles(images: &[Image]) -> Vec<String> {
    let mut titles: Vec<String> = images.iter().map(devices::image_shown).collect();
    for more in [|i: &Image| format!(" · API {}", i.api), |i: &Image| format!(" · {}", i.abi)] {
        let same: Vec<bool> = titles.iter().map(|t| titles.iter().filter(|u| *u == t).count() > 1).collect();
        for (i, same) in same.into_iter().enumerate() {
            if same {
                titles[i] += &more(&images[i]);
            }
        }
    }
    titles
}

/// Another image chosen: its name for the device, unless one was typed.
extern "C" fn image_chosen(_this: Id, _cmd: Id, _sender: Id) {
    let Some((field, popup, suggested)) = FORM.with(|f| f.borrow().as_ref().map(|f| (f.field, f.popup, f.suggested.clone()))) else { return };
    unsafe {
        if rust_str(msg0(field, sel("stringValue"))) != suggested {
            return;
        }
        let index = msg_i64_ret(popup, sel("indexOfSelectedItem")).max(0) as usize;
        let Some(name) = with_list(|l| l.images.get(index).map(|i| devices::default_name(i, &l.devices))).flatten() else { return };
        msg_id(field, sel("setStringValue:"), ns_str(&name));
        FORM.with(|f| {
            if let Some(f) = f.borrow_mut().as_mut() {
                f.suggested = name;
            }
        });
    }
}

/// A row's menu: what the ⋯ button and a right click offer.
unsafe fn fill_menu(menu: Id, row: i64) {
    unsafe {
        msg_void(menu, sel("removeAllItems"));
        let Some((_, running)) = device_at(row) else { return };
        let me = list_object();
        let items: [(&str, &str, bool); 5] = [
            (if running.is_some() { "Show" } else { "Start" }, "startDevice:", true),
            ("Edit…", "editDevice:", true),
            ("Wipe Data…", "wipeDevice:", running.is_none()),
            ("Show in Finder", "revealDevice:", true),
            ("Delete…", "deleteDevice:", running.is_none()),
        ];
        for (i, (title, action, enabled)) in items.into_iter().enumerate() {
            if i == 1 || i == 4 {
                msg_id(menu, sel("addItem:"), msg0(cls("NSMenuItem"), sel("separatorItem")));
            }
            let item = menu_item(title, action, "", 0, 0, me);
            msg_i64(item, sel("setTag:"), row);
            msg_bool(item, sel("setEnabled:"), enabled as i8);
            msg_id(menu, sel("addItem:"), item);
            msg0(item, sel("release"));
        }
        msg_bool(menu, sel("setAutoenablesItems:"), 0);
    }
}

extern "C" fn device_menu(_this: Id, _cmd: Id, sender: Id) {
    unsafe {
        let row = msg_i64_ret(sender, sel("tag"));
        let menu = msg0(msg0(msg0(cls("NSMenu"), sel("alloc")), sel("init")), sel("autorelease"));
        fill_menu(menu, row);
        let bounds = msg_rect(sender, sel("bounds"));
        let f: unsafe extern "C" fn(Id, Id, Id, NSPoint, Id) -> i8 = std::mem::transmute(objc_msgSend as *const ());
        f(menu, sel("popUpMenuPositioningItem:atLocation:inView:"), std::ptr::null_mut(), NSPoint { x: 0.0, y: bounds.size.height + 4.0 }, sender);
    }
}

/// The table's own menu, for a right click: the clicked row's.
extern "C" fn menu_needs_update(_this: Id, _cmd: Id, menu: Id) {
    let Some(row) = with_list(|l| unsafe { msg_i64_ret(l.table, sel("clickedRow")) }) else { return };
    unsafe { fill_menu(menu, row) };
}

/// Edit…: the device's name and settings, in the form New Device has, its image shown
/// but kept. What changes applies at its next start.
extern "C" fn edit_device(_this: Id, _cmd: Id, sender: Id) {
    let Some((d, running)) = device_at(unsafe { msg_i64_ret(sender, sel("tag")) }) else { return };
    let shown = with_list(|l| d.image_shown(&l.images)).unwrap_or_default();
    let mut entered = (d.name.clone(), Raw::from_settings(&d.settings));
    ADVANCED.with(|a| a.set(false));
    loop {
        let (alert, form) = unsafe { edit_alert(&d, &shown, running.is_some(), &entered, ADVANCED.with(|a| a.get())) };
        FORM.with(|f| *f.borrow_mut() = Some(form));
        let answer = unsafe { msg_i64_ret(alert, sel("runModal")) };
        let Some(form) = FORM.with(|f| f.borrow_mut().take()) else { return };
        let name = unsafe { rust_str(msg0(form.field, sel("stringValue"))) };
        let raw = unsafe { form.settings.read() };
        if answer == TOGGLE_ADVANCED {
            unsafe { msg_id(msg0(alert, sel("window")), sel("orderOut:"), std::ptr::null_mut()) };
            entered = (name, raw);
            continue;
        }
        if answer != 1000 {
            return;
        }
        // The name and the settings in one write: either both change, or neither has,
        // as the alert says.
        // What the form showed: the device's settings as the form reads them back, its
        // defaults made none, so a field left alone counts as unchanged.
        let shown = d.shown_as(Raw::from_settings(&d.settings).to_settings(&d.settings).unwrap_or_else(|_| d.settings.clone()));
        let saved = raw.to_settings(&d.settings).and_then(|settings| with_list(|l| l.store.edit(&shown, &name, &settings)).ok_or_else(String::new)?);
        match saved {
            Ok(_) => return refresh(Some(&d.id)),
            Err(e) if e.is_empty() => return,
            Err(e) => {
                show_alert("The device wasn't changed", &e, &["OK"]);
                entered = (name, raw);
            }
        }
    }
}

/// The form editing `d`, with Save and Cancel.
unsafe fn edit_alert(d: &Device, image: &str, running: bool, entered: &(String, Raw), advanced: bool) -> (Id, Form) {
    unsafe {
        let alert = msg0(new_alert(), sel("autorelease"));
        msg_id(alert, sel("setMessageText:"), ns_str(&format!("Edit “{}”", d.name)));
        let when = if running { "It's running: changes apply when it next starts." } else { "Changes apply when it next starts." };
        msg_id(alert, sel("setInformativeText:"), ns_str(when));
        msg_id_ret(alert, sel("addButtonWithTitle:"), ns_str("Save"));
        msg_id_ret(alert, sel("addButtonWithTitle:"), ns_str("Cancel"));
        let field = msg_id_ret(cls("NSTextField"), sel("textFieldWithString:"), ns_str(&entered.0));
        pin_const(field, "widthAnchor", 280.0);
        let mut rows = vec![[label("Name:"), field], [label("System image:"), label(image)]];
        let (settings, more, hidden) = SettingsRows::new(&entered.1, advanced);
        rows.extend(more);
        set_accessory_hiding(alert, &rows, hidden);
        msg_id(msg0(alert, sel("window")), sel("setInitialFirstResponder:"), field);
        (alert, Form { field, popup: std::ptr::null_mut(), suggested: String::new(), settings, advanced })
    }
}

extern "C" fn wipe_device(_this: Id, _cmd: Id, sender: Id) {
    let Some((d, _)) = device_at(unsafe { msg_i64_ret(sender, sel("tag")) }) else { return };
    let text = "Its apps, accounts, settings and files are deleted, and it starts as new. This can't be undone.";
    if show_alert(&format!("Wipe the data of “{}”?", d.name), text, &["Wipe Data", "Cancel"]) != 0 {
        return;
    }
    if let Some(Err(e)) = with_list(|l| l.store.wipe(&d)) {
        show_alert("The data wasn't wiped", &e, &["OK"]);
    }
    refresh(None);
}

extern "C" fn reveal_device(_this: Id, _cmd: Id, sender: Id) {
    let Some((d, _)) = device_at(unsafe { msg_i64_ret(sender, sel("tag")) }) else { return };
    // Its data, or its folder before its first start.
    let path = if d.data.exists() { d.data.clone() } else { d.data.parent().map(std::path::Path::to_path_buf).unwrap_or_default() };
    let _ = std::process::Command::new("/usr/bin/open").arg("-R").arg(path).status();
}

extern "C" fn delete_device(_this: Id, _cmd: Id, sender: Id) {
    let Some((d, _)) = device_at(unsafe { msg_i64_ret(sender, sel("tag")) }) else { return };
    let text = "The device and its apps, accounts, settings and files are deleted. This can't be undone.";
    if show_alert(&format!("Delete “{}”?", d.name), text, &["Delete", "Cancel"]) != 0 {
        return;
    }
    if let Some(Err(e)) = with_list(|l| l.store.delete(&d)) {
        show_alert("The device wasn't deleted", &e, &["OK"]);
    }
    refresh(None);
}

/// Closing the list quits: there's nothing else in this zeroemu.
extern "C" fn window_will_close(_this: Id, _cmd: Id, _note: Id) {
    DONE.store(true, Ordering::Release);
}

extern "C" fn became_key(_this: Id, _cmd: Id, _note: Id) {
    refresh(None);
}

extern "C" fn became_active(_this: Id, _cmd: Id, _note: Id) {
    if DONE.load(Ordering::Acquire) || background() {
        return;
    }
    if let Some(window) = with_list(|l| l.window) {
        unsafe {
            let is_miniaturized: unsafe extern "C" fn(Id, Id) -> i8 = std::mem::transmute(objc_msgSend as *const ());
            if is_miniaturized(window, sel("isMiniaturized")) != 0 {
                msg_id(window, sel("deminiaturize:"), std::ptr::null_mut());
            }
        }
    }
}

/// Every two seconds: shows devices that started or stopped in another zeroemu.
extern "C" fn tick(_this: Id, _cmd: Id, _timer: Id) {
    let changed = with_list(|l| l.devices.iter().map(Device::running).collect::<Vec<_>>() != l.running).unwrap_or(false);
    if changed {
        refresh(None);
    }
}

// ---- A device's settings in the form ----

/// Memory a device can be given, in MB: as Android Studio offers, up to what zeroemu
/// maps. The default, 4096, is stored as no setting.
const RAM_CHOICES: [u64; 11] = [1024, 1536, 2048, 3072, 4096, 6144, 8192, 12288, 16384, 24576, 32768];
const RAM_DEFAULT: u64 = 4096;

/// What the form's location popup offers, in order (separators aside).
#[derive(Clone, Debug, PartialEq)]
enum Place {
    /// No setting: its time zone's city (location::default_for_zone).
    ZoneCity,
    Fixed(Source),
    /// Coordinates typed in the field below.
    Custom,
}

fn places() -> Vec<Place> {
    let mut out = vec![Place::ZoneCity, Place::Fixed(Source::Off)];
    out.extend(location::PRESETS.iter().map(|p| Place::Fixed(Source::Preset(p.id))));
    out.push(Place::Custom);
    out
}

/// The settings as the form's controls hold them, before they are checked: what a
/// refused form opens again with.
#[derive(Clone, Debug, PartialEq)]
struct Raw {
    width: String,
    height: String,
    dpi: String,
    ram_mb: u64,
    /// 0 for all of the Mac's.
    cpus: usize,
    network: bool,
    /// Empty for the Mac's.
    zone: String,
    place: Place,
    coords: String,
    /// The time zone box's entry for the Mac's, as the form showed it: the Mac's zone
    /// may change while it shows.
    mine: String,
    /// Device says Custom, though the size and density may still be a preset's: it
    /// was chosen, and Advanced Settings opened for them.
    custom: bool,
}

impl Raw {
    fn from_settings(s: &Settings) -> Raw {
        let d = s.display.unwrap_or(Display::DEFAULT);
        let (place, coords) = match &s.location {
            None => (Place::ZoneCity, String::new()),
            // As saved (to_ini's six decimals), so that an edit that doesn't touch
            // them doesn't move the device.
            Some(Source::Point { lat, lon }) => (Place::Custom, format!("{}, {}", trim_decimals(*lat), trim_decimals(*lon))),
            Some(other) => (Place::Fixed(other.clone()), String::new()),
        };
        Raw {
            width: d.width.to_string(),
            height: d.height.to_string(),
            dpi: d.dpi.to_string(),
            ram_mb: s.ram_mb.unwrap_or(RAM_DEFAULT),
            cpus: s.cpus.unwrap_or(0),
            network: s.network != Some(false),
            zone: s.time_zone.clone().unwrap_or_default(),
            place,
            coords,
            mine: same_zone_label(),
            custom: d.preset().is_none(),
        }
    }

    /// The settings, or what is wrong with them. Defaults are stored as no setting, so
    /// the device follows them if they change. What `base` (the device's settings
    /// before) has that the form doesn't show stays.
    fn to_settings(&self, base: &Settings) -> Result<Settings, String> {
        let num = |what: &str, v: &str| v.trim().parse::<u32>().map_err(|_| format!("the screen's {what} is a number, not {:?}", v.trim()));
        let display = Display::new(num("width", &self.width)?, num("height", &self.height)?, num("density", &self.dpi)?)?;
        let zone = self.zone.trim();
        let time_zone = if zone.is_empty() || zone == self.mine {
            None
        } else {
            // One saved as it was (perhaps on a newer Mac) stays; one typed is checked.
            if base.time_zone.as_deref() != Some(zone) {
                devices::check_time_zone(zone)?;
            }
            Some(zone.to_string())
        };
        let location = match &self.place {
            Place::ZoneCity => None,
            Place::Fixed(s) => Some(s.clone()),
            Place::Custom => match Source::parse(&self.coords)? {
                p @ Source::Point { .. } => Some(p),
                _ => return Err(format!("coordinates are a latitude and a longitude, such as 28.6129, 77.2295, not {:?}", self.coords.trim())),
            },
        };
        Ok(Settings {
            display: (display != Display::DEFAULT).then_some(display),
            ram_mb: (self.ram_mb != RAM_DEFAULT).then_some(devices::check_ram(self.ram_mb)?),
            cpus: (self.cpus != 0).then_some(self.cpus),
            network: (!self.network).then_some(false),
            time_zone,
            location,
            others: base.others.clone(),
        })
    }
}

/// A coordinate to six decimals (about 10 cm), without the zeros at the end.
fn trim_decimals(v: f64) -> String {
    let s = format!("{v:.6}");
    s.trim_end_matches('0').trim_end_matches('.').to_string()
}

/// What the time zone box says for no setting, before the Mac's zone.
const SAME_ZONE: &str = "Same as this Mac";

/// The time zone box's entry for no setting, exactly: only it means the Mac's (text
/// that merely starts the same is a zone, and checked as one).
fn same_zone_label() -> String {
    format!("{SAME_ZONE} ({})", devices::host_time_zone().unwrap_or_else(|| "unknown".into()))
}

/// The form's rows for a device's settings, as Android Studio's device wizard has
/// them: the screen (a preset, or a size and density), memory, cores, network, time
/// zone and location.
struct SettingsRows {
    preset: Id,
    width: Id,
    height: Id,
    dpi: Id,
    dp: Id,
    ram: Id,
    ram_choices: Vec<u64>,
    cpus: Id,
    network: Id,
    zone: Id,
    place: Id,
    /// The place popup's items: Some(index into `places()`), None for a separator.
    place_items: Vec<Option<usize>>,
    coords: Id,
    /// Raw::mine.
    mine: String,
    /// Advanced Settings' note on what isn't the default, while it is closed (else
    /// null): it follows Device, the one of its settings shown.
    summary: Id,
}

impl SettingsRows {
    /// The controls, filled from `raw`, and their rows: Device, then Advanced Settings
    /// and the rows under it, which are the last of them, and how many those are when
    /// `advanced` is closed (to hide), else 0. Closed, they keep what `raw` has: the
    /// defaults, for a new device, unless they were changed before.
    unsafe fn new(raw: &Raw, advanced: bool) -> (SettingsRows, Vec<[Id; 2]>, usize) {
        unsafe {
            let me = list_object();
            // The screen: a preset fills the size and density; typing a size or
            // density makes it Custom.
            let preset = popup(&Display::PRESETS.iter().map(|(_, name, d)| format!("{name} · {} × {} · {} dpi", d.width, d.height, d.dpi)).chain(["Custom".to_string()]).map(Some).collect::<Vec<_>>());
            msg_id(preset, sel("setTarget:"), me);
            msg_id(preset, sel("setAction:"), sel("presetChosen:"));
            let width = number_field(&raw.width, 64.0);
            let height = number_field(&raw.height, 64.0);
            let dpi = msg0(msg0(cls("NSComboBox"), sel("alloc")), sel("init"));
            let dpis: Vec<Id> = ["120", "160", "213", "240", "280", "320", "360", "400", "420", "440", "480", "560", "640"].iter().map(|d| ns_str(d)).collect();
            msg_id(dpi, sel("addItemsWithObjectValues:"), ns_array(&dpis));
            msg_id(dpi, sel("setStringValue:"), ns_str(&raw.dpi));
            msg_i64(dpi, sel("setNumberOfVisibleItems:"), 13);
            pin_const(dpi, "widthAnchor", 80.0);
            msg0(dpi, sel("autorelease"));
            for f in [width, height, dpi] {
                msg_id(f, sel("setDelegate:"), me);
            }
            let dp = label("");
            msg_id(dp, sel("setTextColor:"), msg0(cls("NSColor"), sel("secondaryLabelColor")));
            let size_row = row_stack(&[width, label("×"), height, label("pixels")], 6.0);
            let dpi_row = row_stack(&[dpi, label("dpi"), dp], 6.0);

            let mut ram_choices: Vec<u64> = RAM_CHOICES.iter().copied().filter(|mb| devices::check_ram(*mb).is_ok()).collect();
            if !ram_choices.contains(&raw.ram_mb) {
                ram_choices.push(raw.ram_mb);
                ram_choices.sort();
            }
            let ram = popup(&ram_choices.iter().map(|mb| Some(ram_shown(*mb))).collect::<Vec<_>>());
            msg_i64(ram, sel("selectItemAtIndex:"), ram_choices.iter().position(|mb| *mb == raw.ram_mb).unwrap_or(0) as i64);

            let host = crate::kernel::host_cpus();
            let most = host.max(raw.cpus);
            let cpus = popup(&std::iter::once(format!("All of this Mac's ({host})")).chain((1..=most).map(|n| n.to_string())).map(Some).collect::<Vec<_>>());
            msg_i64(cpus, sel("selectItemAtIndex:"), raw.cpus.min(most) as i64);

            let network = msg_id_id_ret_sel(cls("NSButton"), sel("checkboxWithTitle:target:action:"), ns_str("Connected to the internet"), std::ptr::null_mut(), std::ptr::null_mut());
            msg_i64(network, sel("setState:"), raw.network as i64);

            let zone = msg0(msg0(cls("NSComboBox"), sel("alloc")), sel("init"));
            let mine = raw.mine.clone();
            let zones: Vec<Id> = std::iter::once(mine.clone()).chain(devices::time_zones()).map(|z| ns_str(&z)).collect();
            msg_id(zone, sel("addItemsWithObjectValues:"), ns_array(&zones));
            msg_bool(zone, sel("setCompletes:"), 1);
            msg_i64(zone, sel("setNumberOfVisibleItems:"), 15);
            msg_id(zone, sel("setStringValue:"), ns_str(if raw.zone.is_empty() { &mine } else { &raw.zone }));
            pin_const(zone, "widthAnchor", 280.0);
            msg0(zone, sel("autorelease"));

            // Where: its time zone's city, none, the places, the routes, or typed in.
            let all = places();
            let mut place_items = Vec::new();
            let mut titles = Vec::new();
            for (i, p) in all.iter().enumerate() {
                let route = matches!(p, Place::Fixed(Source::Preset(id)) if location::PRESETS.iter().any(|q| q.id == *id && matches!(q.kind, location::Kind::Route { .. })));
                let first_route = route && !all[..i].iter().any(|q| matches!(q, Place::Fixed(Source::Preset(id)) if location::PRESETS.iter().any(|r| r.id == *id && matches!(r.kind, location::Kind::Route { .. }))));
                // A line before the places, before the routes, and before Custom.
                if i == 2 || first_route || *p == Place::Custom {
                    place_items.push(None);
                    titles.push(None);
                }
                place_items.push(Some(i));
                titles.push(Some(match p {
                    Place::ZoneCity => "Its time zone's main city".to_string(),
                    Place::Fixed(Source::Off) => "None (no GPS signal)".to_string(),
                    Place::Fixed(s) if route => format!("{} (moving)", s.shown()),
                    Place::Fixed(s) => s.shown(),
                    Place::Custom => "Custom coordinates".to_string(),
                }));
            }
            let place = popup(&titles);
            let chosen = all.iter().position(|p| *p == raw.place).unwrap_or(0);
            msg_i64(place, sel("selectItemAtIndex:"), place_items.iter().position(|i| *i == Some(chosen)).unwrap_or(0) as i64);
            msg_id(place, sel("setTarget:"), me);
            msg_id(place, sel("setAction:"), sel("locationChosen:"));
            let coords = msg_id_ret(cls("NSTextField"), sel("textFieldWithString:"), ns_str(&raw.coords));
            msg_id(coords, sel("setPlaceholderString:"), ns_str("latitude, longitude"));
            pin_const(coords, "widthAnchor", 280.0);
            msg_bool(coords, sel("setEnabled:"), (raw.place == Place::Custom) as i8);

            let mut rows = SettingsRows { preset, width, height, dpi, dp, ram, ram_choices, cpus, network, zone, place, place_items, coords, mine, summary: std::ptr::null_mut() };
            rows.screen_changed();
            // Custom chosen stays chosen, until a size typed is a preset's.
            if raw.custom {
                msg_i64(preset, sel("selectItemAtIndex:"), Display::PRESETS.len() as i64);
            }
            // Advanced Settings: a disclosure triangle and its title, which both open
            // and close it, and, closed, what it holds that isn't the default.
            let triangle = msg0(msg0(cls("NSButton"), sel("alloc")), sel("init"));
            msg_i64(triangle, sel("setBezelStyle:"), 5); // NSBezelStyleDisclosure
            msg_i64(triangle, sel("setButtonType:"), 1); // NSButtonTypePushOnPushOff
            msg_id(triangle, sel("setTitle:"), ns_str(""));
            msg_i64(triangle, sel("setState:"), advanced as i64);
            msg_id(triangle, sel("setTarget:"), me);
            msg_id(triangle, sel("setAction:"), sel("advancedToggled:"));
            msg0(triangle, sel("autorelease"));
            let title = button("Advanced Settings", "advancedToggled:", 0);
            msg_bool(title, sel("setBordered:"), 0);
            let summary = label(&if advanced { String::new() } else { advanced_summary(raw) });
            msg_id(summary, sel("setTextColor:"), msg0(cls("NSColor"), sel("secondaryLabelColor")));
            msg_i64(summary, sel("setLineBreakMode:"), 4);
            squeeze(summary);
            if !advanced {
                rows.summary = summary;
            }
            let disclosure = row_stack(&[triangle, title, summary], 4.0);
            let lines = vec![
                [label("Device:"), preset],
                [msg0(cls("NSGridCell"), sel("emptyContentView")), disclosure],
                [label("Screen:"), size_row],
                [label("Density:"), dpi_row],
                [label("Memory:"), ram],
                [label("CPU cores:"), cpus],
                [label("Network:"), network],
                [label("Time zone:"), zone],
                [label("Location:"), place],
                [label("Coordinates:"), coords],
            ];
            let hidden = if advanced { 0 } else { lines.len() - 2 };
            (rows, lines, hidden)
        }
    }

    /// What the controls hold now.
    unsafe fn read(&self) -> Raw {
        unsafe {
            let text = |f: Id| rust_str(msg0(f, sel("stringValue")));
            let index = |p: Id| msg_i64_ret(p, sel("indexOfSelectedItem")).max(0) as usize;
            let all = places();
            Raw {
                width: text(self.width),
                height: text(self.height),
                dpi: text(self.dpi),
                ram_mb: self.ram_choices.get(index(self.ram)).copied().unwrap_or(RAM_DEFAULT),
                cpus: index(self.cpus),
                network: msg_i64_ret(self.network, sel("state")) != 0,
                zone: text(self.zone),
                place: self.place_items.get(index(self.place)).copied().flatten().and_then(|i| all.get(i).cloned()).unwrap_or(Place::ZoneCity),
                coords: text(self.coords),
                mine: self.mine.clone(),
                custom: index(self.preset) >= Display::PRESETS.len(),
            }
        }
    }

    /// After the size or density changed: the preset it is, if any, and its size in dp.
    unsafe fn screen_changed(&self) {
        unsafe {
            let raw = self.read();
            let d = (|| Display::new(raw.width.trim().parse().ok()?, raw.height.trim().parse().ok()?, raw.dpi.trim().parse().ok()?).ok())();
            let preset = d.and_then(|d| Display::PRESETS.iter().position(|p| p.2 == d)).unwrap_or(Display::PRESETS.len());
            msg_i64(self.preset, sel("selectItemAtIndex:"), preset as i64);
            let text = match d {
                Some(d) => format!("{} × {} dp", d.dp().0, d.dp().1),
                None => "not a screen Android can have".to_string(),
            };
            msg_id(self.dp, sel("setStringValue:"), ns_str(&text));
            // Closed, its note says the screen chosen now.
            if !self.summary.is_null() {
                msg_id(self.summary, sel("setStringValue:"), ns_str(&advanced_summary(&self.read())));
            }
        }
    }
}

/// The settings rows of the form showing now, copied: their handlers message AppKit,
/// which may call back in, so never while FORM is borrowed.
fn form_rows<R>(f: impl FnOnce(&SettingsRows) -> R) -> Option<R> {
    FORM.with(|form| form.borrow().as_ref().map(|form| f(&form.settings)))
}

/// A preset chosen: its size and density in the fields.
extern "C" fn preset_chosen(_this: Id, _cmd: Id, _sender: Id) {
    let Some((preset, width, height, dpi)) = form_rows(|r| (r.preset, r.width, r.height, r.dpi)) else { return };
    let advanced = FORM.with(|f| f.borrow().as_ref().is_some_and(|f| f.advanced));
    unsafe {
        let i = msg_i64_ret(preset, sel("indexOfSelectedItem")).max(0) as usize;
        match Display::PRESETS.get(i) {
            Some((_, _, d)) => {
                msg_id(width, sel("setStringValue:"), ns_str(&d.width.to_string()));
                msg_id(height, sel("setStringValue:"), ns_str(&d.height.to_string()));
                msg_id(dpi, sel("setStringValue:"), ns_str(&d.dpi.to_string()));
            }
            // Custom: its size and density are under Advanced Settings, and it stays
            // chosen until a size typed is a preset's (screen_changed would choose the
            // preset the fields still hold).
            None if !advanced => return toggle_advanced(),
            None => return,
        }
    }
    screen_changed();
}

/// Advanced Settings opened or closed: the form shows again, the other way.
extern "C" fn advanced_toggled(_this: Id, _cmd: Id, _sender: Id) {
    toggle_advanced();
}

fn toggle_advanced() {
    let Some(advanced) = FORM.with(|f| f.borrow().as_ref().map(|f| f.advanced)) else { return };
    ADVANCED.with(|a| a.set(!advanced));
    unsafe { msg_i64(msg0(cls("NSApplication"), sel("sharedApplication")), sel("stopModalWithCode:"), TOGGLE_ADVANCED) };
}

/// Memory as the form shows it: "4 GB", "1.5 GB", or in MB when it isn't a half.
fn ram_shown(mb: u64) -> String {
    match mb % 1024 {
        0 => format!("{} GB", mb / 1024),
        512 => format!("{}.5 GB", mb / 1024),
        _ => format!("{mb} MB"),
    }
}

/// What Advanced Settings holds that isn't the default, for when it is closed.
fn advanced_summary(raw: &Raw) -> String {
    let mut parts = Vec::new();
    let screen = (|| Display::new(raw.width.trim().parse().ok()?, raw.height.trim().parse().ok()?, raw.dpi.trim().parse().ok()?).ok())();
    // A preset's screen shows in Device; one chosen as Custom, though it is a preset's
    // size, is said here, as Device says only Custom.
    if let Some(d) = screen.filter(|d| raw.custom || d.preset().is_none()) {
        parts.push(format!("{} × {} at {} dpi", d.width, d.height, d.dpi));
    }
    if raw.ram_mb != RAM_DEFAULT {
        parts.push(ram_shown(raw.ram_mb));
    }
    match raw.cpus {
        0 => {}
        1 => parts.push("1 core".into()),
        n => parts.push(format!("{n} cores")),
    }
    if !raw.network {
        parts.push("no network".into());
    }
    let zone = raw.zone.trim();
    if !zone.is_empty() && zone != raw.mine {
        parts.push(zone.to_string());
    }
    match &raw.place {
        Place::ZoneCity => {}
        Place::Fixed(Source::Off) => parts.push("no location".into()),
        Place::Fixed(s) => parts.push(s.shown()),
        Place::Custom => parts.push(raw.coords.trim().to_string()),
    }
    if parts.is_empty() { "(defaults)".into() } else { format!("({})", parts.join(", ")) }
}

fn screen_changed() {
    let Some(rows) = FORM.with(|form| form.borrow().as_ref().map(|f| SettingsRowsIds::of(&f.settings))) else { return };
    unsafe { rows.with(|r| r.screen_changed()) };
}

/// A size or density typed (NSControlTextDidChangeNotification).
extern "C" fn screen_typed(_this: Id, _cmd: Id, _note: Id) {
    screen_changed();
}

/// A density picked from the list: the box's text is the old one until this returns.
extern "C" fn density_picked(_this: Id, _cmd: Id, note: Id) {
    unsafe {
        let combo = msg0(note, sel("object"));
        let picked = msg0(combo, sel("objectValueOfSelectedItem"));
        if !picked.is_null() {
            msg_id(combo, sel("setStringValue:"), picked);
        }
    }
    screen_changed();
}

/// A location chosen: the coordinates field is for Custom only.
extern "C" fn location_chosen(_this: Id, _cmd: Id, _sender: Id) {
    let Some((place, items, coords)) = form_rows(|r| (r.place, r.place_items.clone(), r.coords)) else { return };
    unsafe {
        let i = msg_i64_ret(place, sel("indexOfSelectedItem")).max(0) as usize;
        let custom = items.get(i).copied().flatten().and_then(|i| places().get(i).cloned()) == Some(Place::Custom);
        msg_bool(coords, sel("setEnabled:"), custom as i8);
        if custom {
            msg_id(msg0(coords, sel("window")), sel("makeFirstResponder:"), coords);
        }
    }
}

/// The ids of a SettingsRows, out of FORM, to work on without holding it.
struct SettingsRowsIds(SettingsRows);

impl SettingsRowsIds {
    fn of(r: &SettingsRows) -> SettingsRowsIds {
        SettingsRowsIds(SettingsRows { ram_choices: r.ram_choices.clone(), place_items: r.place_items.clone(), mine: r.mine.clone(), ..*r })
    }

    unsafe fn with(&self, f: impl FnOnce(&SettingsRows)) {
        f(&self.0)
    }
}

/// A popup button of these items (None a separator), added through its menu, as
/// addItemWithTitle: drops an item whose title another has.
unsafe fn popup(items: &[Option<String>]) -> Id {
    unsafe {
        let p = msg_init_popup(msg0(cls("NSPopUpButton"), sel("alloc")), sel("initWithFrame:pullsDown:"), NSRect { origin: NSPoint { x: 0.0, y: 0.0 }, size: NSSize { width: 280.0, height: 26.0 } }, 0);
        msg_bool(p, sel("setAutoenablesItems:"), 0);
        let menu = msg0(p, sel("menu"));
        for item in items {
            match item {
                None => msg_id(menu, sel("addItem:"), msg0(cls("NSMenuItem"), sel("separatorItem"))),
                Some(title) => {
                    let it = menu_item(title, "", "", 0, 0, std::ptr::null_mut());
                    msg_id(it, sel("setAction:"), std::ptr::null_mut());
                    msg_id(menu, sel("addItem:"), it);
                    msg_void(it, sel("release"));
                }
            }
        }
        pin_const(p, "widthAnchor", 280.0);
        msg0(p, sel("autorelease"))
    }
}

unsafe fn number_field(value: &str, width: f64) -> Id {
    unsafe {
        let f = msg_id_ret(cls("NSTextField"), sel("textFieldWithString:"), ns_str(value));
        pin_const(f, "widthAnchor", width);
        f
    }
}

// ---- Alerts ----

/// An alert with zeroemu's icon, which a zeroemu outside its app bundle has only as
/// the application's icon image (set_app_icon), not as a file.
pub(super) unsafe fn new_alert() -> Id {
    unsafe {
        let alert = msg0(msg0(cls("NSAlert"), sel("alloc")), sel("init"));
        let icon = msg0(msg0(cls("NSApplication"), sel("sharedApplication")), sel("applicationIconImage"));
        if !icon.is_null() {
            msg_id(alert, sel("setIcon:"), icon);
        }
        alert
    }
}

/// An alert with these buttons, the first the default. Which was chosen, from 0.
fn show_alert(title: &str, text: &str, buttons: &[&str]) -> i64 {
    unsafe {
        let alert = msg0(new_alert(), sel("autorelease"));
        msg_id(alert, sel("setMessageText:"), ns_str(title));
        msg_id(alert, sel("setInformativeText:"), ns_str(text));
        for (i, b) in buttons.iter().enumerate() {
            let button = msg_id_ret(alert, sel("addButtonWithTitle:"), ns_str(b));
            if i == 0 && matches!(*b, "Delete" | "Wipe Data") {
                msg_bool(button, sel("setHasDestructiveAction:"), 1);
            }
        }
        msg_i64_ret(alert, sel("runModal")) - 1000
    }
}

/// An alert asking for one line of text: what was typed, or None for Cancel.
unsafe fn ask_text(title: &str, text: &str, value: &str, ok: &str) -> Option<String> {
    unsafe {
        let alert = msg0(new_alert(), sel("autorelease"));
        msg_id(alert, sel("setMessageText:"), ns_str(title));
        msg_id(alert, sel("setInformativeText:"), ns_str(text));
        msg_id_ret(alert, sel("addButtonWithTitle:"), ns_str(ok));
        msg_id_ret(alert, sel("addButtonWithTitle:"), ns_str("Cancel"));
        let field = msg_id_ret(cls("NSTextField"), sel("textFieldWithString:"), ns_str(value));
        msg_size(field, sel("setFrameSize:"), NSSize { width: 280.0, height: 24.0 });
        msg_id(alert, sel("setAccessoryView:"), field);
        msg_void(alert, sel("layout"));
        msg_id(msg0(alert, sel("window")), sel("setInitialFirstResponder:"), field);
        (msg_i64_ret(alert, sel("runModal")) == 1000).then(|| rust_str(msg0(field, sel("stringValue"))))
    }
}

fn copy_text(text: &str) {
    unsafe {
        let board = msg0(cls("NSPasteboard"), sel("generalPasteboard"));
        msg_void(board, sel("clearContents"));
        msg_id_id_ret(board, sel("setString:forType:"), ns_str(text), ns_str("public.utf8-plain-text"));
    }
}

// ---- The menu bar while the list shows ----

/// The application's menu, File with New Device, Edit (which the form's text fields
/// need for copy and paste), Window and Help. Quit quits at once: no device runs yet.
unsafe fn set_up_list_menus(app: Id) {
    let none = std::ptr::null_mut();
    unsafe {
        let me = list_object();
        let controls = controls_object();
        let bar = msg0(msg0(cls("NSMenu"), sel("alloc")), sel("init"));
        submenu(bar, "zeroemu", &[
            menu_item("About zeroemu", "deviceAction:", "", 0, TAG_ABOUT, controls),
            none,
            menu_item("Hide zeroemu", "hide:", "h", COMMAND_MASK, 0, none),
            menu_item("Hide Others", "hideOtherApplications:", "h", COMMAND_MASK | OPTION_MASK, 0, none),
            menu_item("Show All", "unhideAllApplications:", "", 0, 0, none),
            none,
            menu_item("Quit zeroemu", "terminate:", "q", COMMAND_MASK, 0, none),
        ]);
        submenu(bar, "File", &[
            menu_item("New Device…", "newDevice:", "n", COMMAND_MASK, 0, me),
            none,
            menu_item("Close", "performClose:", "w", COMMAND_MASK, 0, none),
        ]);
        submenu(bar, "Edit", &[
            menu_item("Undo", "undo:", "z", COMMAND_MASK, 0, none),
            menu_item("Redo", "redo:", "Z", COMMAND_MASK, 0, none),
            none,
            menu_item("Cut", "cut:", "x", COMMAND_MASK, 0, none),
            menu_item("Copy", "copy:", "c", COMMAND_MASK, 0, none),
            menu_item("Paste", "paste:", "v", COMMAND_MASK, 0, none),
            menu_item("Select All", "selectAll:", "a", COMMAND_MASK, 0, none),
        ]);
        let window = submenu(bar, "Window", &[
            menu_item("Minimize", "performMiniaturize:", "m", COMMAND_MASK, 0, none),
            menu_item("Zoom", "performZoom:", "", 0, 0, none),
            none,
            menu_item("Bring All to Front", "arrangeInFront:", "", 0, 0, none),
        ]);
        let help = submenu(bar, "Help", &[
            menu_item("zeroemu Help", "deviceAction:", "", 0, TAG_HELP, controls),
            menu_item("Known Gaps", "deviceAction:", "", 0, TAG_GAPS, controls),
        ]);
        msg_id(app, sel("setMainMenu:"), bar);
        msg_id(app, sel("setWindowsMenu:"), window);
        msg_id(app, sel("setHelpMenu:"), help);
    }
}

// ---- The test FIFO ----

/// ZEROEMU_LIST_FIFO=<path>: lines from this host FIFO work the list for tests run
/// behind someone's work: `new <name>` makes a device of the tested image (or the
/// first that boots), `start <name>` starts one, `quit` closes the list.
fn start_fifo() {
    let Ok(path) = std::env::var("ZEROEMU_LIST_FIFO") else { return };
    let _ = std::thread::Builder::new().name("list-fifo".into()).spawn(move || {
        use std::io::BufRead;
        while !DONE.load(Ordering::Acquire) {
            let Ok(f) = std::fs::File::open(&path) else { return };
            for line in std::io::BufReader::new(f).lines().map_while(Result::ok) {
                if DONE.load(Ordering::Acquire) {
                    return;
                }
                // The list's last line: what follows is for a list opened after it,
                // which reads the same FIFO (app::open_list passes it on).
                let last = matches!(line.split_whitespace().next(), Some("start" | "quit"));
                on_ui_thread(Box::new(move || fifo_line(&line)));
                if last {
                    return;
                }
            }
        }
    });
}

/// Frees the FIFO reader if it waits for a writer, to find the list done and end.
fn stop_fifo() {
    use std::os::unix::fs::OpenOptionsExt;
    if let Ok(path) = std::env::var("ZEROEMU_LIST_FIFO") {
        // Opening to write without a reader fails at once (ENXIO) rather than waits.
        let _ = std::fs::OpenOptions::new().write(true).custom_flags(libc::O_NONBLOCK).open(path);
    }
}

fn fifo_line(line: &str) {
    let (word, rest) = line.trim().split_once(' ').unwrap_or((line.trim(), ""));
    let rest = rest.trim();
    match word {
        "new" => {
            let made = with_list(|l| {
                let supports = l.supports.get_or_insert_with(|| l.images.iter().map(sdk::classify).collect());
                let i = default_image(supports).ok_or("no image boots")?;
                l.store.create(rest, &l.images[i])
            });
            match made {
                Some(Ok(d)) => refresh(Some(&d.id)),
                Some(Err(e)) => eprintln!("zeroemu: list: new {rest}: {e}"),
                None => {}
            }
        }
        "start" => match with_list(|l| l.store.find(rest)) {
            Some(Ok(d)) => match with_list(|l| l.devices.iter().position(|x| x.id == d.id)).flatten() {
                Some(row) => start(row as i64),
                None => eprintln!("zeroemu: list: start {rest}: not shown"),
            },
            Some(Err(e)) => eprintln!("zeroemu: list: start {rest}: {e}"),
            None => {}
        },
        "quit" => DONE.store(true, Ordering::Release),
        _ => eprintln!("zeroemu: list: unknown line {line:?}"),
    }
}

// ---- Views ----

const WEIGHT_SEMIBOLD: f64 = 0.3;
const IMAGE_LEADING: i64 = 7;
const ALIGN_LEADING: i64 = 5;
const ALIGN_CENTER_X: i64 = 9;
const ALIGN_CENTER_Y: i64 = 10;

unsafe fn msg_f64(obj: Id, sel: Id, a: f64) {
    let f: unsafe extern "C" fn(Id, Id, f64) = unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    unsafe { f(obj, sel, a) }
}

unsafe fn msg_size_ret(obj: Id, sel: Id) -> NSSize {
    let f: unsafe extern "C" fn(Id, Id) -> NSSize = unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    unsafe { f(obj, sel) }
}

unsafe fn msg_init_popup(obj: Id, sel: Id, frame: NSRect, pulls_down: i8) -> Id {
    let f: unsafe extern "C" fn(Id, Id, NSRect, i8) -> Id = unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    unsafe { f(obj, sel, frame, pulls_down) }
}

unsafe fn msg_id_id_ret_sel(obj: Id, sel: Id, a: Id, b: Id, c: Id) -> Id {
    let f: unsafe extern "C" fn(Id, Id, Id, Id, Id) -> Id = unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    unsafe { f(obj, sel, a, b, c) }
}

unsafe fn label(text: &str) -> Id {
    unsafe { msg_id_ret(cls("NSTextField"), sel("labelWithString:"), ns_str(text)) }
}

unsafe fn wrapping_label(text: &str) -> Id {
    unsafe {
        let l = msg_id_ret(cls("NSTextField"), sel("wrappingLabelWithString:"), ns_str(text));
        msg_id(l, sel("setTextColor:"), msg0(cls("NSColor"), sel("secondaryLabelColor")));
        l
    }
}

unsafe fn font(size: f64, weight: f64) -> Id {
    let f: unsafe extern "C" fn(Id, Id, f64, f64) -> Id = unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    unsafe { f(cls("NSFont"), sel("systemFontOfSize:weight:"), size, weight) }
}

unsafe fn symbol(name: &str, points: f64) -> Id {
    unsafe { super::symbol(name, name, points) }
}

unsafe fn image_view(image: Id, tint: &str) -> Id {
    unsafe {
        let v = msg_id_ret(cls("NSImageView"), sel("imageViewWithImage:"), image);
        msg_id(v, sel("setContentTintColor:"), msg0(cls("NSColor"), sel(tint)));
        v
    }
}

unsafe fn button(title: &str, action: &str, tag: i64) -> Id {
    unsafe {
        let b = msg_id_id_ret_sel(cls("NSButton"), sel("buttonWithTitle:target:action:"), ns_str(title), list_object(), sel(action));
        msg_i64(b, sel("setTag:"), tag);
        b
    }
}

/// Views side by side, centred on a line; the one that `hug` lets go takes the room.
unsafe fn row_stack(views: &[Id], spacing: f64) -> Id {
    unsafe {
        let s = msg_id_ret(cls("NSStackView"), sel("stackViewWithViews:"), ns_array(views));
        msg_i64(s, sel("setOrientation:"), 0);
        msg_i64(s, sel("setAlignment:"), ALIGN_CENTER_Y);
        msg_i64(s, sel("setDistribution:"), 0); // fill
        msg_f64(s, sel("setSpacing:"), spacing);
        s
    }
}

unsafe fn column_stack(views: &[Id], spacing: f64, align: i64) -> Id {
    unsafe {
        let s = msg_id_ret(cls("NSStackView"), sel("stackViewWithViews:"), ns_array(views));
        msg_i64(s, sel("setOrientation:"), 1);
        msg_i64(s, sel("setAlignment:"), align);
        msg_f64(s, sel("setSpacing:"), spacing);
        s
    }
}

/// Lets `v` grow across: it takes a row's spare width.
unsafe fn hug(v: Id, priority: f32) {
    let f: unsafe extern "C" fn(Id, Id, f32, i64) = unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    unsafe { f(v, sel("setContentHuggingPriority:forOrientation:"), priority, 0) }
}

/// Lets `v` be narrower than its text, which it then cuts short, rather than push
/// the row's buttons out.
unsafe fn squeeze(v: Id) {
    let f: unsafe extern "C" fn(Id, Id, f32, i64) = unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    unsafe { f(v, sel("setContentCompressionResistancePriority:forOrientation:"), 250.0, 0) }
}

unsafe fn add(parent: Id, child: Id) {
    unsafe {
        msg_bool(child, sel("setTranslatesAutoresizingMaskIntoConstraints:"), 0);
        msg_id(parent, sel("addSubview:"), child);
    }
}

/// `a`'s anchor at `b`'s, `c` points on (Auto Layout).
unsafe fn pin(a: Id, a_anchor: &str, b: Id, b_anchor: &str, c: f64) {
    unsafe {
        let f: unsafe extern "C" fn(Id, Id, Id, f64) -> Id = std::mem::transmute(objc_msgSend as *const ());
        let constraint = f(msg0(a, sel(a_anchor)), sel("constraintEqualToAnchor:constant:"), msg0(b, sel(b_anchor)), c);
        msg_bool(constraint, sel("setActive:"), 1);
    }
}

unsafe fn pin_const(a: Id, anchor: &str, c: f64) {
    unsafe {
        let constraint = msg_f64_id(msg0(a, sel(anchor)), sel("constraintEqualToConstant:"), c);
        msg_bool(constraint, sel("setActive:"), 1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image(sdk: &std::path::Path, level: &str, tag: &str, release: &str) -> Image {
        let dir = sdk.join("system-images").join(level).join(tag).join(sdk::host_abi());
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("build.prop"), format!("ro.build.version.release={release}\n")).unwrap();
        Image::from_dir(&dir)
    }

    #[test]
    fn the_form_reads_back_what_a_device_has() {
        // Nothing set: the form shows the defaults, and saves nothing.
        let none = Raw::from_settings(&Settings::default());
        assert_eq!((none.width.as_str(), none.height.as_str(), none.dpi.as_str(), none.ram_mb, none.cpus), ("1080", "2400", "420", 4096, 0));
        assert_eq!(none.to_settings(&Settings::default()).unwrap(), Settings::default());
        // Everything set comes back the same.
        let all = Settings {
            display: Some(Display::new(720, 1280, 320).unwrap()),
            ram_mb: Some(2048),
            cpus: Some(4),
            network: Some(false),
            time_zone: Some("Asia/Kolkata".into()),
            location: Some(Source::Point { lat: 12.9716, lon: 77.5946 }),
            others: vec!["future=yes".into()],
        };
        let raw = Raw::from_settings(&all);
        assert_eq!(raw.place, Place::Custom);
        assert_eq!(raw.to_settings(&all).unwrap(), all);
        // What can't be: said, not saved.
        let bad = Raw { width: "7".into(), ..raw.clone() };
        assert!(bad.to_settings(&all).is_err());
        let bad = Raw { coords: "north".into(), ..raw.clone() };
        assert!(bad.to_settings(&all).is_err());
        let mine = Raw { zone: same_zone_label(), place: Place::Fixed(Source::Off), ..raw.clone() };
        let s = mine.to_settings(&all).unwrap();
        assert_eq!((s.time_zone, s.location), (None, Some(Source::Off)));
        let typo = Raw { zone: format!("{SAME_ZONE} typo"), ..raw };
        assert!(typo.to_settings(&all).is_err(), "not the Mac's: a zone, and none");
    }

    #[test]
    fn closed_advanced_settings_say_what_isnt_the_default() {
        let defaults = Raw::from_settings(&Settings::default());
        assert_eq!(advanced_summary(&defaults), "(defaults)");
        // A preset screen shows in Device, so isn't repeated.
        let tablet = Raw { width: "2560".into(), height: "1600".into(), dpi: "320".into(), ..defaults.clone() };
        assert_eq!(advanced_summary(&tablet), "(defaults)");
        // Custom, though a preset's size: said, as Device says only Custom.
        let custom = Raw { width: "1080".into(), height: "2424".into(), dpi: "420".into(), custom: true, ..defaults.clone() };
        assert_eq!(advanced_summary(&custom), "(1080 × 2424 at 420 dpi)");
        let changed = Raw {
            width: "1440".into(),
            height: "3120".into(),
            dpi: "560".into(),
            ram_mb: 2048,
            cpus: 2,
            network: false,
            zone: "Europe/Berlin".into(),
            place: Place::Fixed(Source::Preset("city-run")),
            ..defaults
        };
        assert_eq!(advanced_summary(&changed), "(1440 × 3120 at 560 dpi, 2 GB, 2 cores, no network, Europe/Berlin, City Run)");
    }

    #[test]
    fn images_that_read_the_same_get_their_level() {
        let sdk = std::env::temp_dir().join(format!("zeroemu-titles-{}", std::process::id()));
        let images = [
            image(&sdk, "android-36.1", "google_apis", "16"),
            image(&sdk, "android-36.1", "google_apis_playstore", "16"),
            image(&sdk, "android-36", "google_apis", "16"),
        ];
        assert_eq!(image_titles(&images), [
            "Android 16 · Google APIs · API 36.1",
            "Android 16 · Google Play",
            "Android 16 · Google APIs · API 36",
        ]);
        let _ = std::fs::remove_dir_all(&sdk);
    }

    #[test]
    fn the_form_chooses_the_tested_image_else_the_first_that_boots() {
        let no = || Support::Unsupported("16 KB page size isn't supported yet".into());
        assert_eq!(default_image(&[no(), Support::Untested, Support::Tested]), Some(2));
        assert_eq!(default_image(&[no(), Support::Untested, Support::Untested]), Some(1));
        // None boots: nothing to create, the form shows them from the first.
        assert_eq!(default_image(&[no(), no()]), None);
        assert_eq!(default_image(&[]), None);
    }

    #[test]
    fn images_none_of_which_boot_say_what_to_install() {
        let other = cant_start_text(None, Some("sdkmanager \"x\""));
        assert!(other.contains("Install the image zeroemu is tested with") && other.ends_with(":\n\nsdkmanager \"x\""));
        let tested = cant_start_text(Some("not fully installed"), Some("sdkmanager \"x\""));
        assert!(tested.contains("(not fully installed)") && tested.contains("Remove it in SDK Manager, then install it again"));
        // No sdkmanager command to give: the package, to install it some other way.
        assert!(cant_start_text(None, None).ends_with(&format!(": {}.", sdk::tested_package())));
    }
}
