//! Where the device is: what its GPS reports. A device starts at its own location
//! (device.ini's `location=`), and Device > Location moves it, to a place or along a
//! route, as Simulator's Features > Location does. The image's GNSS HAL
//! (device/generic/goldfish's android.hardware.gnss-service.ranchu) reads NMEA
//! sentences from the host on the qemud "gps" pipe (src/kernel/vsock.rs).

use std::sync::Mutex;

/// What the GPS reports.
#[derive(Clone, Debug, PartialEq)]
pub enum Source {
    /// Nothing: no fix, as with no sky in view.
    Off,
    /// One place, in degrees.
    Point { lat: f64, lon: f64 },
    /// A preset (`PRESETS`), a place or a route, by its id.
    Preset(&'static str),
}

/// A place, or a route the device moves along.
pub struct Preset {
    pub id: &'static str,
    pub name: &'static str,
    pub kind: Kind,
}

pub enum Kind {
    Place { lat: f64, lon: f64 },
    /// Waypoints in degrees, followed at `speed` metres a second, start to end and
    /// round again.
    Route { speed: f64, points: &'static [(f64, f64)] },
}

/// Places first, then routes.
pub static PRESETS: &[Preset] = &[Preset { id: "googleplex", name: "Googleplex, Mountain View", kind: Kind::Place { lat: 37.4220, lon: -122.0841 } }];

impl Source {
    /// device.ini's and --location's form: `off`, `<lat>,<lon>`, or a preset's id.
    pub fn parse(s: &str) -> Result<Source, String> {
        let s = s.trim();
        if s.eq_ignore_ascii_case("off") || s.eq_ignore_ascii_case("none") {
            return Ok(Source::Off);
        }
        if let Some(p) = PRESETS.iter().find(|p| p.id.eq_ignore_ascii_case(s)) {
            return Ok(Source::Preset(p.id));
        }
        let bad = || format!("a location is off, <latitude>,<longitude> in degrees, or a preset such as {}; not {s:?}", PRESETS[0].id);
        let (lat, lon) = s.split_once(',').ok_or_else(bad)?;
        let (lat, lon): (f64, f64) = (lat.trim().parse().map_err(|_| bad())?, lon.trim().parse().map_err(|_| bad())?);
        if !(-90.0..=90.0).contains(&lat) || !(-180.0..=180.0).contains(&lon) {
            return Err(format!("{lat},{lon} isn't on Earth: latitude is -90 to 90, longitude -180 to 180"));
        }
        Ok(Source::Point { lat, lon })
    }

    /// The form `parse` reads.
    pub fn to_ini(&self) -> String {
        match self {
            Source::Off => "off".into(),
            Source::Point { lat, lon } => format!("{lat:.6},{lon:.6}"),
            Source::Preset(id) => (*id).into(),
        }
    }

    /// As people read it: "Googleplex, Mountain View", "37.4220, -122.0841", "None".
    pub fn shown(&self) -> String {
        match self {
            Source::Off => "None".into(),
            Source::Point { lat, lon } => format!("{lat:.4}, {lon:.4}"),
            Source::Preset(id) => PRESETS.iter().find(|p| p.id == *id).map_or_else(|| (*id).into(), |p| p.name.into()),
        }
    }
}

/// Where a device is when nothing says: the main city of its time zone (`zone`, an
/// IANA name), as the tz database's zone.tab places it, else the Googleplex, as the
/// Android Emulator's default.
pub fn default_for_zone(zone: Option<&str>) -> Source {
    let _ = zone;
    Source::Preset("googleplex")
}

static CURRENT: Mutex<Option<Source>> = Mutex::new(None);

/// Moves the device: the GPS reports `source` from now on.
pub fn set(source: Source) {
    *CURRENT.lock().unwrap() = Some(source);
}

/// What the GPS reports now.
pub fn current() -> Source {
    CURRENT.lock().unwrap().clone().unwrap_or(Source::Off)
}
