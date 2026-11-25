//! Where the device is: what its GPS reports. A device starts at its own location
//! (device.ini's `location=`), and Device > Location moves it, to a place or along a
//! route, as Simulator's Features > Location does. The image's GNSS HAL
//! (device/generic/goldfish's android.hardware.gnss-service.ranchu) reads NMEA
//! sentences from the host on the qemud "gps" pipe (src/kernel/vsock.rs), which sends
//! `nmea` of `fix` once a second.

use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

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

/// Places first, then routes. The Googleplex is first, and where a device is when
/// nothing else says, as in the Android Emulator. The places are where their names
/// say, to four decimals (about 10 m).
pub static PRESETS: &[Preset] = &[
    Preset { id: "googleplex", name: "Googleplex, Mountain View", kind: Kind::Place { lat: 37.4220, lon: -122.0841 } },
    Preset { id: "times-square", name: "Times Square, New York", kind: Kind::Place { lat: 40.7580, lon: -73.9855 } },
    Preset { id: "christ-the-redeemer", name: "Christ the Redeemer, Rio de Janeiro", kind: Kind::Place { lat: -22.9519, lon: -43.2105 } },
    Preset { id: "trafalgar-square", name: "Trafalgar Square, London", kind: Kind::Place { lat: 51.5078, lon: -0.1281 } },
    Preset { id: "eiffel-tower", name: "Eiffel Tower, Paris", kind: Kind::Place { lat: 48.8583, lon: 2.2945 } },
    Preset { id: "brandenburg-gate", name: "Brandenburg Gate, Berlin", kind: Kind::Place { lat: 52.5163, lon: 13.3777 } },
    Preset { id: "great-pyramid", name: "Great Pyramid, Giza", kind: Kind::Place { lat: 29.9792, lon: 31.1342 } },
    Preset { id: "india-gate", name: "India Gate, New Delhi", kind: Kind::Place { lat: 28.6129, lon: 77.2295 } },
    Preset { id: "gateway-of-india", name: "Gateway of India, Mumbai", kind: Kind::Place { lat: 18.9220, lon: 72.8346 } },
    Preset { id: "vidhana-soudha", name: "Vidhana Soudha, Bengaluru", kind: Kind::Place { lat: 12.9797, lon: 77.5906 } },
    Preset { id: "shibuya-crossing", name: "Shibuya Crossing, Tokyo", kind: Kind::Place { lat: 35.6595, lon: 139.7005 } },
    Preset { id: "sydney-opera-house", name: "Sydney Opera House", kind: Kind::Place { lat: -33.8572, lon: 151.2151 } },
    Preset { id: "city-run", name: "City Run", kind: Kind::Route { speed: 3.0, points: CITY_RUN } },
    Preset { id: "city-bicycle-ride", name: "City Bicycle Ride", kind: Kind::Route { speed: 6.0, points: CITY_BICYCLE_RIDE } },
    Preset { id: "freeway-drive", name: "Freeway Drive", kind: Kind::Route { speed: 28.0, points: FREEWAY_DRIVE } },
];

// The routes are zeroemu's own, round the Googleplex, each a loop. Their waypoints
// follow real paths and roads: they were found by routing between a few points on
// OpenStreetMap's map (© OpenStreetMap contributors, ODbL) and keeping the points
// where the way turns by more than a few metres, five decimals (about a metre) each.

/// 5.6 km on foot, about half an hour at 3 m/s: from the Googleplex up the Permanente
/// Creek Trail, round Shoreline Lake by the Bay Trail and its west shore, back across
/// Shoreline Park and down the creek again.
static CITY_RUN: &[(f64, f64)] = &[
    (37.42214, -122.08402), (37.42209, -122.08402), (37.42211, -122.08455), (37.42187, -122.08448),
    (37.42171, -122.08528), (37.42110, -122.08531), (37.42118, -122.08585), (37.42115, -122.08628),
    (37.42133, -122.08652), (37.42357, -122.08645), (37.42366, -122.08639), (37.42377, -122.08615),
    (37.42461, -122.08592), (37.42538, -122.08638), (37.42668, -122.08648), (37.42765, -122.08624),
    (37.42822, -122.08633), (37.42851, -122.08627), (37.42918, -122.08645), (37.43053, -122.08644),
    (37.43082, -122.08632), (37.43135, -122.08631), (37.43139, -122.08644), (37.43157, -122.08637),
    (37.43157, -122.08677), (37.43183, -122.08716), (37.43189, -122.08703), (37.43236, -122.08706),
    (37.43277, -122.08698), (37.43282, -122.08679), (37.43311, -122.08692), (37.43329, -122.08669),
    (37.43395, -122.08642), (37.43469, -122.08592), (37.43490, -122.08587), (37.43504, -122.08591),
    (37.43514, -122.08604), (37.43517, -122.08620), (37.43557, -122.09287), (37.43553, -122.09460),
    (37.43534, -122.09473), (37.43543, -122.09482), (37.43537, -122.09507), (37.43517, -122.09529),
    (37.43487, -122.09540), (37.43453, -122.09542), (37.43384, -122.09606), (37.43357, -122.09620),
    (37.43326, -122.09607), (37.43312, -122.09574), (37.43276, -122.09526), (37.43234, -122.09506),
    (37.43073, -122.09507), (37.42925, -122.09520), (37.42887, -122.09512), (37.42835, -122.09322),
    (37.42854, -122.09101), (37.42846, -122.09011), (37.42858, -122.08915), (37.42853, -122.08828),
    (37.42856, -122.08759), (37.42841, -122.08705), (37.42843, -122.08629), (37.42818, -122.08633),
    (37.42760, -122.08624), (37.42668, -122.08648), (37.42542, -122.08639), (37.42461, -122.08592),
    (37.42377, -122.08615), (37.42366, -122.08639), (37.42357, -122.08645), (37.42133, -122.08652),
    (37.42115, -122.08628), (37.42118, -122.08585), (37.42110, -122.08531), (37.42171, -122.08528),
    (37.42187, -122.08448), (37.42211, -122.08455), (37.42209, -122.08402),
];

/// 6.7 km by bicycle, about 19 minutes at 6 m/s: from the Googleplex along Amphitheatre
/// Parkway and Crittenden Lane to the Stevens Creek Trail, north on it to the bay, west
/// on the Bay Trail, round the bend of North Shoreline Boulevard and down it.
static CITY_BICYCLE_RIDE: &[(f64, f64)] = &[
    (37.42214, -122.08402), (37.42209, -122.08402), (37.42204, -122.08384), (37.42210, -122.08353),
    (37.42191, -122.08303), (37.42161, -122.08284), (37.42161, -122.08267), (37.42177, -122.08264),
    (37.42208, -122.08284), (37.42248, -122.08290), (37.42259, -122.08300), (37.42273, -122.08330),
    (37.42293, -122.08335), (37.42305, -122.08331), (37.42311, -122.08186), (37.42302, -122.08168),
    (37.42321, -122.07964), (37.42322, -122.07781), (37.42329, -122.07760), (37.42335, -122.07669),
    (37.42334, -122.07188), (37.42348, -122.07183), (37.42372, -122.07153), (37.42479, -122.07153),
    (37.42479, -122.07000), (37.42484, -122.06988), (37.42478, -122.06884), (37.42630, -122.06881),
    (37.42778, -122.06913), (37.42891, -122.06892), (37.42947, -122.06873), (37.42952, -122.06934),
    (37.43054, -122.06964), (37.43115, -122.07023), (37.43547, -122.07167), (37.43583, -122.07187),
    (37.43588, -122.07249), (37.43565, -122.07585), (37.43542, -122.07704), (37.43543, -122.07740),
    (37.43534, -122.07782), (37.43535, -122.07818), (37.43518, -122.07921), (37.43520, -122.07956),
    (37.43510, -122.07995), (37.43506, -122.08083), (37.43488, -122.08165), (37.43470, -122.08170),
    (37.43421, -122.08166), (37.43381, -122.08234), (37.43333, -122.08292), (37.43326, -122.08299),
    (37.43313, -122.08279), (37.43377, -122.08197), (37.43414, -122.08128), (37.43438, -122.08048),
    (37.43444, -122.07968), (37.43429, -122.07884), (37.43394, -122.07812), (37.43346, -122.07760),
    (37.43283, -122.07727), (37.43236, -122.07720), (37.43181, -122.07726), (37.42994, -122.07792),
    (37.42892, -122.07820), (37.42771, -122.07818), (37.42638, -122.07806), (37.42582, -122.07809),
    (37.42583, -122.07824), (37.42554, -122.07827), (37.42442, -122.07826), (37.42358, -122.07813),
    (37.42349, -122.07819), (37.42324, -122.07818), (37.42321, -122.07964), (37.42310, -122.08073),
    (37.42321, -122.08075), (37.42307, -122.08226), (37.42305, -122.08331), (37.42293, -122.08335),
    (37.42273, -122.08330), (37.42259, -122.08300), (37.42248, -122.08290), (37.42208, -122.08284),
    (37.42177, -122.08264), (37.42161, -122.08267), (37.42161, -122.08284), (37.42191, -122.08303),
    (37.42210, -122.08353), (37.42204, -122.08384), (37.42209, -122.08402),
];

/// 40 km on US 101 (the Bayshore Freeway), about 24 minutes at 28 m/s (100 km/h):
/// north from Rengstorff Avenue in Mountain View to Whipple Avenue in Redwood City,
/// where it turns round, south to Ellis Street by Moffett Field, round again, and north.
static FREEWAY_DRIVE: &[(f64, f64)] = &[
    (37.42340, -122.09560), (37.42471, -122.09738), (37.42583, -122.09866), (37.45057, -122.12464),
    (37.45198, -122.12638), (37.45275, -122.12757), (37.48195, -122.17735), (37.48300, -122.17957),
    (37.48384, -122.18184), (37.48466, -122.18464), (37.48519, -122.18704), (37.48557, -122.18948),
    (37.48775, -122.20699), (37.48815, -122.20939), (37.48858, -122.21129), (37.48920, -122.21346),
    (37.49001, -122.21572), (37.49391, -122.22472), (37.49540, -122.22945), (37.49552, -122.22959),
    (37.49604, -122.23106), (37.49636, -122.23151), (37.49709, -122.23182), (37.49729, -122.23219),
    (37.49741, -122.23261), (37.49572, -122.23336), (37.49556, -122.23362), (37.49546, -122.23397),
    (37.49555, -122.23430), (37.49579, -122.23450), (37.49611, -122.23444), (37.49629, -122.23421),
    (37.49633, -122.23396), (37.49591, -122.23191), (37.49424, -122.22614), (37.49324, -122.22346),
    (37.48970, -122.21537), (37.48894, -122.21316), (37.48832, -122.21090), (37.48767, -122.20752),
    (37.48549, -122.19003), (37.48513, -122.18756), (37.48460, -122.18512), (37.48385, -122.18238),
    (37.48266, -122.17924), (37.48225, -122.17840), (37.47533, -122.16640), (37.45258, -122.12766),
    (37.45179, -122.12646), (37.45045, -122.12482), (37.42809, -122.10137), (37.42497, -122.09801),
    (37.42097, -122.09264), (37.41409, -122.08306), (37.41320, -122.08143), (37.41163, -122.07782),
    (37.40885, -122.07095), (37.40826, -122.06930), (37.40781, -122.06761), (37.40526, -122.05594),
    (37.40508, -122.05565), (37.40420, -122.05313), (37.40362, -122.05120), (37.40454, -122.05137),
    (37.40549, -122.05567), (37.40558, -122.05652), (37.40802, -122.06755), (37.40869, -122.06952),
    (37.41323, -122.08090), (37.41381, -122.08212), (37.41483, -122.08378),
];

/// The preset with this id.
pub fn preset(id: &str) -> Option<&'static Preset> {
    PRESETS.iter().find(|p| p.id == id)
}

impl Source {
    /// device.ini's and --location's form: `off`, `<lat>,<lon>`, or a preset's id.
    pub fn parse(s: &str) -> Result<Source, String> {
        let s = s.trim();
        if s.eq_ignore_ascii_case("off") || s.eq_ignore_ascii_case("none") {
            return Ok(Source::Off);
        }
        // By its id, or by its name as Device > Location shows it ("City Run",
        // "Times Square, New York": before the comma could be read as coordinates).
        if let Some(p) = PRESETS.iter().find(|p| p.id.eq_ignore_ascii_case(s) || p.name.eq_ignore_ascii_case(s)) {
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
            Source::Preset(id) => preset(id).map_or_else(|| (*id).into(), |p| p.name.into()),
        }
    }

    /// What the GPS reads `elapsed` seconds after this was chosen: None when it is Off.
    /// A place stands still; a route goes round at its speed.
    pub fn fix_at(&self, elapsed: f64) -> Option<Fix> {
        match self {
            Source::Off => None,
            Source::Point { lat, lon } => Some(Fix::still(*lat, *lon)),
            Source::Preset(id) => match preset(id)?.kind {
                Kind::Place { lat, lon } => Some(Fix::still(lat, lon)),
                Kind::Route { speed, points } => along(points, speed, elapsed),
            },
        }
    }
}

/// One reading of the GPS.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Fix {
    /// Degrees, north and east positive.
    pub lat: f64,
    pub lon: f64,
    /// Metres above the sea. zeroemu knows no heights, so 0 everywhere.
    pub altitude: f64,
    /// Metres a second.
    pub speed: f64,
    /// Where it is going, in degrees clockwise from north: 0 when it stands still.
    pub course: f64,
}

impl Fix {
    fn still(lat: f64, lon: f64) -> Fix {
        Fix { lat, lon, altitude: 0.0, speed: 0.0, course: 0.0 }
    }
}

/// The Earth's mean radius in metres (IUGG), for `distance`.
const EARTH_RADIUS: f64 = 6_371_008.8;

/// Metres between two points along the Earth's surface (the haversine formula).
pub fn distance(a: (f64, f64), b: (f64, f64)) -> f64 {
    let (p1, p2) = (a.0.to_radians(), b.0.to_radians());
    let (dp, dl) = ((b.0 - a.0).to_radians(), (b.1 - a.1).to_radians());
    let h = (dp / 2.0).sin().powi(2) + p1.cos() * p2.cos() * (dl / 2.0).sin().powi(2);
    2.0 * EARTH_RADIUS * h.sqrt().min(1.0).asin()
}

/// The direction from `a` to `b` as it sets out, in degrees clockwise from north.
pub fn bearing(a: (f64, f64), b: (f64, f64)) -> f64 {
    let (p1, p2) = (a.0.to_radians(), b.0.to_radians());
    let dl = (b.1 - a.1).to_radians();
    let y = dl.sin() * p2.cos();
    let x = p1.cos() * p2.sin() - p1.sin() * p2.cos() * dl.cos();
    y.atan2(x).to_degrees().rem_euclid(360.0)
}

/// Where a route's traveller is after `elapsed` seconds at `speed` m/s from its first
/// point: so far along the waypoints, and from the last back to the first, round and
/// round. The heading is the leg's it is on. Within a leg, a straight line between the
/// two points' degrees: legs are short enough that the great circle is within a
/// fraction of a metre of it.
fn along(points: &[(f64, f64)], speed: f64, elapsed: f64) -> Option<Fix> {
    let n = points.len();
    let first = *points.first()?;
    let leg = |i: usize| (points[i], points[(i + 1) % n]);
    let round: f64 = (0..n).map(|i| distance(leg(i).0, leg(i).1)).sum();
    if round <= 0.0 {
        return Some(Fix::still(first.0, first.1));
    }
    let mut left = (speed * elapsed.max(0.0)).rem_euclid(round);
    // The last leg with any length, should rounding carry `left` past the end.
    let mut at = None;
    for i in 0..n {
        let (a, b) = leg(i);
        let d = distance(a, b);
        if d <= 0.0 {
            continue;
        }
        at = Some((a, b, (left / d).min(1.0)));
        if left < d {
            break;
        }
        left -= d;
    }
    let (a, b, f) = at?;
    Some(Fix { lat: a.0 + (b.0 - a.0) * f, lon: a.1 + (b.1 - a.1) * f, altitude: 0.0, speed, course: bearing(a, b) })
}

/// Where a device is when nothing says: the main city of its time zone (`zone`, an
/// IANA name), as the tz database's zone.tab places it, else the Googleplex, as the
/// Android Emulator's default.
pub fn default_for_zone(zone: Option<&str>) -> Source {
    // zone.tab first: it keeps a city for zones that zone1970.tab folds into another
    // country's (Europe/Oslo into Europe/Berlin). Windows has neither.
    let found = zone.and_then(|zone| {
        ["zone.tab", "zone1970.tab"].iter().find_map(|f| zone_place(&std::fs::read_to_string(format!("/usr/share/zoneinfo/{f}")).ok()?, zone))
    });
    match found {
        Some((lat, lon)) => Source::Point { lat, lon },
        None => Source::Preset(PRESETS[0].id),
    }
}

/// The place zone.tab or zone1970.tab gives `zone`. Their lines are country codes,
/// coordinates, the zone's name and maybe comments, between tabs; # starts a comment.
fn zone_place(tab: &str, zone: &str) -> Option<(f64, f64)> {
    tab.lines().filter(|l| !l.starts_with('#')).find_map(|line| {
        let mut fields = line.split('\t');
        let (_countries, place, name) = (fields.next()?, fields.next()?, fields.next()?);
        if name.trim() == zone { iso6709(place.trim()) } else { None }
    })
}

/// Coordinates as the tz database writes them (ISO 6709): a sign and degrees and
/// minutes of latitude, then of longitude, maybe each with seconds: ±DDMM±DDDMM or
/// ±DDMMSS±DDDMMSS.
fn iso6709(s: &str) -> Option<(f64, f64)> {
    let split = 1 + s.get(1..)?.find(['+', '-'])?;
    let (lat, lon) = s.split_at(split);
    Some((sexagesimal(lat, 2)?, sexagesimal(lon, 3)?))
}

/// One ISO 6709 angle, a sign and then `whole` digits of degrees, two of minutes and
/// maybe two of seconds, in degrees.
fn sexagesimal(s: &str, whole: usize) -> Option<f64> {
    let sign = match s.as_bytes().first()? {
        b'+' => 1.0,
        b'-' => -1.0,
        _ => return None,
    };
    let digits = &s[1..];
    if !digits.bytes().all(|b| b.is_ascii_digit()) || !matches!(digits.len().checked_sub(whole)?, 2 | 4) {
        return None;
    }
    let part = |from: usize, to: usize| digits.get(from..to).map_or(0.0, |d| d.parse::<f64>().unwrap_or(0.0));
    let (deg, min, sec) = (part(0, whole), part(whole, whole + 2), part(whole + 2, whole + 4));
    Some(sign * (deg + min / 60.0 + sec / 3600.0))
}

/// Satellites a fix says it used, and the spread of their geometry (HDOP): a good day
/// under an open sky. The HAL makes up that many satellites for Android's GnssStatus.
const SATELLITES: u32 = 8;
const HDOP: f64 = 1.0;

/// `fix` at `unix_secs` (UTC) as the NMEA sentences a receiver sends each second,
/// $GPGGA and then $GPRMC, each ending in CR LF. The fields are those the image's GNSS
/// HAL reads (device/generic/goldfish's GnssHwListener.cpp), whose sscanf formats,
/// after the sentence's name, are
///   GGA "%06d,%d.%n%d%n,%c,%d.%n%d%n,%c,%d,%d,%n" and then, after the HDOP, "%lf,%c,"
///   RMC "%06d,%c,%d.%n%d%n,%c,%d.%n%d%n,%c,%lf,%lf,%d,%lf,%c*"
/// so the time is whole seconds with no fraction, and every RMC field is there, the
/// magnetic variation too. The HAL wants status A, a GGA altitude in M, and fractions
/// of a minute of under eight digits.
pub fn nmea(fix: &Fix, unix_secs: u64) -> String {
    let (h, m, s) = (unix_secs / 3600 % 24, unix_secs / 60 % 60, unix_secs % 60);
    let (year, month, day) = civil(unix_secs / 86_400);
    let time = format!("{h:02}{m:02}{s:02}");
    let lat = format!("{},{}", minutes(fix.lat.abs(), 2), if fix.lat < 0.0 { 'S' } else { 'N' });
    let lon = format!("{},{}", minutes(fix.lon.abs(), 3), if fix.lon < 0.0 { 'W' } else { 'E' });
    // Fix quality 1 (a GPS fix); then the height of the geoid above the ellipsoid,
    // which the HAL doesn't read, and no differential GPS.
    let gga = format!("GPGGA,{time},{lat},{lon},1,{SATELLITES:02},{HDOP:.1},{:.1},M,0.0,M,,", fix.altitude);
    let knots = fix.speed * 3600.0 / 1852.0;
    let rmc = format!("GPRMC,{time},A,{lat},{lon},{knots:.2},{:.1},{day:02}{month:02}{:02},0.0,E", fix.course, year % 100);
    sentence(&gga) + &sentence(&rmc)
}

/// `$`, the body, `*` and the XOR of the body's bytes in two hex digits, CR LF.
fn sentence(body: &str) -> String {
    let sum = body.bytes().fold(0u8, |x, b| x ^ b);
    format!("${body}*{sum:02X}\r\n")
}

/// Degrees as NMEA writes them: whole degrees in `width` digits, then minutes to four
/// decimals (about 0.2 m), "3725.3200" for 37.4220. Worked in ten-thousandths of a
/// minute, so that rounding never makes 60 minutes.
fn minutes(deg: f64, width: usize) -> String {
    let units = (deg * 600_000.0).round() as u64;
    let (whole, rest) = (units / 600_000, units % 600_000);
    format!("{whole:0width$}{:02}.{:04}", rest / 10_000, rest % 10_000)
}

/// The date `days` after 1970-01-01, (year, month, day): Howard Hinnant's
/// civil_from_days, for the proleptic Gregorian calendar.
fn civil(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let (era, doe) = (z / 146_097, z % 146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + (month <= 2) as u64, month, day)
}

/// What the GPS reports, since when (for a route's progress), and a count of the
/// changes, for waiting on the next.
struct Current {
    source: Option<Source>,
    since: Option<Instant>,
    changes: u64,
}

static CURRENT: Mutex<Current> = Mutex::new(Current { source: None, since: None, changes: 0 });
static CHANGED: Condvar = Condvar::new();

/// Held by the tests that `set`, which would otherwise move each other's devices.
#[cfg(test)]
pub static TESTS_THAT_SET: Mutex<()> = Mutex::new(());

/// Moves the device: the GPS reports `source` from now on. A route starts again from
/// its beginning, also when it is the one already going.
pub fn set(source: Source) {
    let mut c = CURRENT.lock().unwrap();
    c.source = Some(source);
    c.since = Some(Instant::now());
    c.changes += 1;
    CHANGED.notify_all();
}

/// What the GPS reports now: Off until something is `set`.
pub fn current() -> Source {
    CURRENT.lock().unwrap().source.clone().unwrap_or(Source::Off)
}

/// What the GPS reads now (None while Off), and how many changes there have been, for
/// `wait_for_change`.
pub fn fix() -> (Option<Fix>, u64) {
    let c = CURRENT.lock().unwrap();
    let elapsed = c.since.map_or(0.0, |t| t.elapsed().as_secs_f64());
    (c.source.as_ref().and_then(|s| s.fix_at(elapsed)), c.changes)
}

/// Sleeps until there have been more than `seen` changes, or `timeout` has passed;
/// with no timeout, until the change.
pub fn wait_for_change(seen: u64, timeout: Option<Duration>) {
    let c = CURRENT.lock().unwrap();
    match timeout {
        Some(t) => drop(CHANGED.wait_timeout_while(c, t, |c| c.changes == seen)),
        None => drop(CHANGED.wait_while(c, |c| c.changes == seen)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn what_parse_reads_to_ini_writes() {
        let mut all = vec![Source::Off, Source::Point { lat: 37.422, lon: -122.0841 }, Source::Point { lat: -33.8572, lon: 151.2151 }, Source::Point { lat: 90.0, lon: -180.0 }];
        all.extend(PRESETS.iter().map(|p| Source::Preset(p.id)));
        for s in all {
            assert_eq!(Source::parse(&s.to_ini()), Ok(s.clone()), "{}", s.to_ini());
        }
        assert_eq!(Source::parse(" None "), Ok(Source::Off));
        assert_eq!(Source::parse("City-Run"), Ok(Source::Preset("city-run")));
        assert_eq!(Source::parse(" 12.5 , -7 "), Ok(Source::Point { lat: 12.5, lon: -7.0 }));
        for bad in ["", "37.4", "north,east", "91,0", "0,180.5", "nowhere", "1,2,3"] {
            assert!(Source::parse(bad).is_err(), "{bad:?}");
        }
        assert_eq!(Source::Preset("googleplex").shown(), "Googleplex, Mountain View");
        assert_eq!(Source::Point { lat: 37.422, lon: -122.0841 }.shown(), "37.4220, -122.0841");
        assert_eq!(Source::Off.shown(), "None");
    }

    #[test]
    fn presets_are_places_then_routes_with_their_own_ids() {
        assert_eq!(PRESETS[0].id, "googleplex");
        let first_route = PRESETS.iter().position(|p| matches!(p.kind, Kind::Route { .. })).unwrap();
        assert!(PRESETS[first_route..].iter().all(|p| matches!(p.kind, Kind::Route { .. })));
        assert_eq!(first_route, 12);
        for (i, p) in PRESETS.iter().enumerate() {
            assert!(PRESETS[..i].iter().all(|q| q.id != p.id && q.name != p.name), "{}", p.id);
            assert!(p.id.bytes().all(|b| b.is_ascii_lowercase() || b == b'-'), "{}: device.ini's form", p.id);
            if let Kind::Route { speed, points } = p.kind {
                assert!(points.len() >= 50, "{}: enough points to follow its way", p.id);
                // None of its legs, the one back to the start too, so long that a corner
                // must have gone missing: the longest are on straight stretches of US 101.
                let n = points.len();
                let longest = (0..n).map(|i| distance(points[i], points[(i + 1) % n])).fold(0.0, f64::max);
                assert!(longest < 6000.0, "{}: a leg of {longest} m", p.id);
                let round: f64 = (0..n).map(|i| distance(points[i], points[(i + 1) % n])).sum();
                let minutes = round / speed / 60.0;
                assert!((10.0..60.0).contains(&minutes), "{}: {minutes} minutes round", p.id);
            }
        }
    }

    #[test]
    fn a_route_goes_round_at_its_speed() {
        // A square of 0.001° on the equator, east, north, west and back south: each side
        // is 111.2 m, the last a little shorter as it is further north.
        let square = [(0.0, 0.0), (0.0, 0.001), (0.001, 0.001), (0.001, 0.0)];
        let side = distance(square[0], square[1]);
        assert!((side - 111.195).abs() < 0.01, "{side}");
        let at = |t: f64| along(&square, 10.0, t).unwrap();
        let start = at(0.0);
        assert_eq!((start.lat, start.lon, start.speed), (0.0, 0.0, 10.0));
        assert!((start.course - 90.0).abs() < 1e-9, "east");
        // 5 s at 10 m/s: 50 m along the first side.
        let f = at(5.0);
        assert!(f.lat.abs() < 1e-12 && (f.lon - 0.001 * 50.0 / side).abs() < 1e-9, "{f:?}");
        assert!((distance((0.0, 0.0), (f.lat, f.lon)) - 50.0).abs() < 1e-6);
        // 15 s: past the first corner and 38.8 m north.
        let f = at(15.0);
        assert!((f.course - 0.0).abs() < 1e-6, "north: {f:?}");
        assert!((distance(square[1], (f.lat, f.lon)) - (150.0 - side)).abs() < 1e-3);
        // Going west, then south.
        assert!((at(25.0).course - 270.0).abs() < 1e-3);
        assert!((at(40.0).course - 180.0).abs() < 1e-6);
        // Once round, it is back where it started, and goes on the same way.
        let round: f64 = (0..4).map(|i| distance(square[i], square[(i + 1) % 4])).sum();
        let again = at(round / 10.0 + 5.0);
        assert!((again.lat - at(5.0).lat).abs() < 1e-9 && (again.lon - at(5.0).lon).abs() < 1e-9, "{again:?}");
        let end = at(round / 10.0 - 1e-6);
        assert!(distance((end.lat, end.lon), square[0]) < 0.01, "{end:?}");
        // Repeated points don't stop it or turn it.
        let doubled = [(0.0, 0.0), (0.0, 0.0), (0.0, 0.001), (0.001, 0.001), (0.001, 0.001), (0.001, 0.0)];
        for t in [0.0, 5.0, 15.0, 25.0, 40.0] {
            let (a, b) = (along(&doubled, 10.0, t).unwrap(), at(t));
            assert!((a.lat - b.lat).abs() < 1e-12 && (a.lon - b.lon).abs() < 1e-12 && (a.course - b.course).abs() < 1e-9, "{t}");
        }
        // A route of one place stands there.
        assert_eq!(along(&[(1.0, 2.0)], 10.0, 30.0), Some(Fix::still(1.0, 2.0)));
    }

    #[test]
    fn a_preset_route_moves_and_a_place_does_not() {
        let run = Source::Preset("city-run");
        let (a, b) = (run.fix_at(0.0).unwrap(), run.fix_at(10.0).unwrap());
        assert_eq!(a.speed, 3.0);
        let moved = distance((a.lat, a.lon), (b.lat, b.lon));
        // 30 m along the way, less across a corner.
        assert!(moved > 5.0 && moved <= 30.0 + 1e-6, "{moved}");
        let place = Source::Preset("india-gate").fix_at(100.0).unwrap();
        assert_eq!((place.lat, place.lon, place.speed, place.course), (28.6129, 77.2295, 0.0, 0.0));
        assert_eq!(Source::Point { lat: 1.5, lon: 2.5 }.fix_at(9.0), Some(Fix::still(1.5, 2.5)));
        assert_eq!(Source::Off.fix_at(0.0), None);
    }

    #[test]
    fn bearings_and_distances() {
        // One degree of latitude is 111.2 km; from Trafalgar Square to the Eiffel Tower
        // is 341.3 km, setting out south-east by south (148.7°), as other calculators
        // of great circles on a sphere of that radius have it.
        assert!((distance((0.0, 0.0), (1.0, 0.0)) - 111_195.08).abs() < 0.1);
        let (london, paris) = ((51.5078, -0.1281), (48.8583, 2.2945));
        assert!((distance(london, paris) - 341_349.5).abs() < 1.0, "{}", distance(london, paris));
        assert!((bearing(london, paris) - 148.71).abs() < 0.01, "{}", bearing(london, paris));
        assert!((bearing((0.0, 0.0), (0.0, -1.0)) - 270.0).abs() < 1e-9);
    }

    /// One value sscanf assigned: an integer, a character, a double, or a %n count.
    #[derive(Clone, Copy, Debug, PartialEq)]
    enum V {
        I(i64),
        C(char),
        F(f64),
        N(usize),
    }

    /// sscanf for the conversions the HAL's formats use, as C has them: %d and %Nd
    /// (skipping white space, a sign, at most N characters), %c (the next character),
    /// %lf (skipping white space, a decimal number) and %n (characters read so far);
    /// other characters must match. The values assigned, and sscanf's result, the
    /// number of them not counting %n.
    fn scan(input: &str, fmt: &str) -> (usize, Vec<V>) {
        let (s, f) = (input.as_bytes(), fmt.as_bytes());
        let (mut i, mut j, mut count, mut got) = (0, 0, 0, Vec::new());
        let space = |i: &mut usize| {
            while *i < s.len() && s[*i].is_ascii_whitespace() {
                *i += 1;
            }
        };
        while j < f.len() {
            if f[j] != b'%' {
                if i >= s.len() || s[i] != f[j] {
                    break;
                }
                (i, j) = (i + 1, j + 1);
                continue;
            }
            j += 1;
            let mut width = 0;
            while f[j].is_ascii_digit() {
                width = width * 10 + (f[j] - b'0') as usize;
                j += 1;
            }
            if f[j] == b'l' {
                j += 1;
            }
            let (conv, max) = (f[j], if width == 0 { usize::MAX } else { width });
            j += 1;
            match conv {
                b'n' => got.push(V::N(i)),
                b'c' => {
                    let Some(&c) = s.get(i) else { break };
                    got.push(V::C(c as char));
                    i += 1;
                }
                b'd' => {
                    space(&mut i);
                    let start = i;
                    if i < s.len() && matches!(s[i], b'+' | b'-') {
                        i += 1;
                    }
                    let digits = i;
                    while i < s.len() && s[i].is_ascii_digit() && i - start < max {
                        i += 1;
                    }
                    if i == digits {
                        break;
                    }
                    got.push(V::I(input[start..i].parse().unwrap()));
                }
                b'f' => {
                    space(&mut i);
                    let start = i;
                    if i < s.len() && matches!(s[i], b'+' | b'-') {
                        i += 1;
                    }
                    let whole = i;
                    while i < s.len() && s[i].is_ascii_digit() {
                        i += 1;
                    }
                    let mut digits = i - whole;
                    if i < s.len() && s[i] == b'.' {
                        let point = i;
                        i += 1;
                        while i < s.len() && s[i].is_ascii_digit() {
                            i += 1;
                        }
                        digits += i - point - 1;
                    }
                    if digits == 0 {
                        break;
                    }
                    got.push(V::F(input[start..i].parse().unwrap()));
                }
                c => panic!("no %{}", c as char),
            }
            if conv != b'n' {
                count += 1;
            }
        }
        (count, got)
    }

    /// Degrees from the HAL's three numbers: ddmm, the fraction of a minute, and its
    /// digits (the difference of the two %n's).
    fn dmm(whole: i64, frac: i64, digits: usize) -> f64 {
        (whole / 100) as f64 + ((whole % 100) as f64 + frac as f64 / 10f64.powi(digits as i32)) / 60.0
    }

    const RMC: &str = "%06d,%c,%d.%n%d%n,%c,%d.%n%d%n,%c,%lf,%lf,%d,%lf,%c*";
    const GGA: &str = "%06d,%d.%n%d%n,%c,%d.%n%d%n,%c,%d,%d,%n";

    /// What the HAL takes from the sentences of one second.
    struct Heard {
        /// From RMC: degrees, knots, degrees, hhmmss and ddmmyy.
        lat: f64,
        lon: f64,
        knots: f64,
        course: f64,
        time: i64,
        date: i64,
        /// From GGA: degrees, how many satellites, metres.
        gga_lat: f64,
        gga_lon: f64,
        satellites: i64,
        altitude: f64,
    }

    /// The HAL's reading of one $GPGGA and one $GPRMC (GnssHwListener.cpp): a line from
    /// its '$' to its '\n', the end two characters before that, the sentence's name and
    /// a comma, then sscanf.
    fn as_the_hal_reads(text: &str) -> Heard {
        let lines: Vec<&str> = text.split_inclusive('\n').collect();
        assert_eq!(lines.len(), 2, "{text:?}");
        let (gga, rmc) = (lines[0], lines[1]);
        for line in [gga, rmc] {
            assert!(line.starts_with('$') && line.ends_with("\r\n"), "{line:?}");
            // The checksum: the XOR of what is between '$' and '*', in hex.
            let (body, sum) = line[1..line.len() - 2].split_once('*').unwrap();
            assert_eq!(u8::from_str_radix(sum, 16).unwrap(), body.bytes().fold(0, |x, b| x ^ b), "{line:?}");
            assert_eq!(sum.len(), 2);
            assert!(line.len() <= 82, "NMEA's longest sentence: {line:?}");
        }
        let fields = rmc.strip_prefix("$GPRMC,").unwrap();
        let (n, v) = scan(fields, RMC);
        assert_eq!(n, 13, "{rmc:?}: {v:?}");
        let [V::I(time), V::C('A'), V::I(lat), V::N(a), V::I(latf), V::N(b), V::C(ns), V::I(lon), V::N(c), V::I(lonf), V::N(d), V::C(ew), V::F(knots), V::F(course), V::I(date), V::F(_), V::C('E' | 'W')] = v[..] else {
            panic!("{rmc:?}: {v:?}")
        };
        assert!((1..8).contains(&(b - a)) && (1..8).contains(&(d - c)), "the HAL's powers of ten");
        let sign = |c: char, plus: char| if c == plus { 1.0 } else { -1.0 };
        let (rmc_time, rmc_lat, rmc_lon) = (time, sign(ns, 'N') * dmm(lat, latf, b - a), sign(ew, 'E') * dmm(lon, lonf, d - c));
        let fields = gga.strip_prefix("$GPGGA,").unwrap();
        let (n, v) = scan(fields, GGA);
        assert_eq!(n, 9, "{gga:?}: {v:?}");
        let [V::I(time), V::I(lat), V::N(a), V::I(latf), V::N(b), V::C(ns), V::I(lon), V::N(c), V::I(lonf), V::N(d), V::C(ew), V::I(1), V::I(sats), V::N(used)] = v[..] else {
            panic!("{gga:?}: {v:?}")
        };
        assert_eq!(time, rmc_time, "the same second");
        // Past the HDOP, the altitude in metres.
        let rest = &fields[used..];
        let rest = &rest[rest.find(',').unwrap() + 1..];
        let (n, v) = scan(rest, "%lf,%c,");
        assert_eq!((n, v.get(1)), (2, Some(&V::C('M'))), "{gga:?}");
        let V::F(altitude) = v[0] else { panic!() };
        Heard {
            lat: rmc_lat,
            lon: rmc_lon,
            knots,
            course,
            time,
            date,
            gga_lat: sign(ns, 'N') * dmm(lat, latf, b - a),
            gga_lon: sign(ew, 'E') * dmm(lon, lonf, d - c),
            satellites: sats,
            altitude,
        }
    }

    #[test]
    fn nmea_is_what_the_hal_reads() {
        // 2023-11-14 22:13:20 UTC, at the Googleplex.
        let text = nmea(&Fix::still(37.4220, -122.0841), 1_700_000_000);
        assert_eq!(
            text,
            "$GPGGA,221320,3725.3200,N,12205.0460,W,1,08,1.0,0.0,M,0.0,M,,*6D\r\n\
             $GPRMC,221320,A,3725.3200,N,12205.0460,W,0.00,0.0,141123,0.0,E*54\r\n"
        );
        let cases = [
            (Fix { lat: 37.4220, lon: -122.0841, altitude: 0.0, speed: 0.0, course: 0.0 }, 1_700_000_000),
            (Fix { lat: -33.8572, lon: 151.2151, altitude: 12.5, speed: 28.0, course: 359.94 }, 951_782_399),
            (Fix { lat: 0.0, lon: 0.0, altitude: 0.0, speed: 3.0, course: 90.0 }, 0),
            (Fix { lat: 12.999_999_99, lon: -0.000_01, altitude: 0.0, speed: 6.0, course: 180.0 }, 4_102_444_800),
            (Fix { lat: -90.0, lon: 180.0, altitude: 0.0, speed: 0.0, course: 0.0 }, 86_399),
        ];
        for (fix, t) in cases {
            let text = nmea(&fix, t);
            let Heard { lat, lon, knots, course, time, date, gga_lat: glat, gga_lon: glon, satellites: sats, altitude } = as_the_hal_reads(&text);
            // Within the 0.0001 minutes NMEA keeps, a fifth of a metre.
            for (got, want) in [(lat, fix.lat), (lon, fix.lon), (glat, fix.lat), (glon, fix.lon)] {
                assert!((got - want).abs() < 2e-6, "{got} for {want}: {text}");
            }
            assert!((knots * 1852.0 / 3600.0 - fix.speed).abs() < 0.01, "{text}");
            assert!((course - fix.course).abs() < 0.051, "{text}");
            assert_eq!(sats, SATELLITES as i64);
            assert_eq!(altitude, fix.altitude);
            let (y, mo, d) = civil(t / 86_400);
            assert_eq!(date, (d * 10_000 + mo * 100 + y % 100) as i64, "{text}");
            assert_eq!(time, (t / 3600 % 24 * 10_000 + t / 60 % 60 * 100 + t % 60) as i64);
        }
    }

    #[test]
    fn minutes_never_round_up_to_sixty() {
        assert_eq!(minutes(12.999_999_99, 2), "1300.0000");
        assert_eq!(minutes(0.000_01, 3), "00000.0006");
        assert_eq!(minutes(180.0, 3), "18000.0000");
        assert_eq!(minutes(37.4220, 2), "3725.3200");
    }

    #[test]
    fn utc_dates() {
        assert_eq!(civil(0), (1970, 1, 1));
        assert_eq!(civil(1_700_000_000 / 86_400), (2023, 11, 14));
        assert_eq!(civil(951_782_400 / 86_400), (2000, 2, 29));
        assert_eq!(civil(4_102_444_800 / 86_400), (2100, 1, 1));
        assert_eq!(civil(4_107_456_000 / 86_400), (2100, 2, 28));
        assert_eq!(civil(4_107_542_400 / 86_400), (2100, 3, 1), "2100 has no 29 February");
    }

    #[test]
    fn zone_tab_places() {
        let close = |a: Option<(f64, f64)>, b: (f64, f64)| a.is_some_and(|a| (a.0 - b.0).abs() < 1e-9 && (a.1 - b.1).abs() < 1e-9);
        assert!(close(iso6709("+3723-12205"), (37.0 + 23.0 / 60.0, -(122.0 + 5.0 / 60.0))));
        assert!(close(iso6709("+404251-0740023"), (40.0 + 42.0 / 60.0 + 51.0 / 3600.0, -(74.0 + 23.0 / 3600.0))));
        assert!(close(iso6709("-3352+15113"), (-(33.0 + 52.0 / 60.0), 151.0 + 13.0 / 60.0)));
        assert!(close(iso6709("+2232+08822"), (22.0 + 32.0 / 60.0, 88.0 + 22.0 / 60.0)));
        for bad in ["", "+3723", "3723-12205", "+372-12205", "+3723-1220", "+3723-122051", "+37a3-12205", "+3723+-12205"] {
            assert_eq!(iso6709(bad), None, "{bad:?}");
        }
        let tab = "# tzdb timezone descriptions\n#\n\
                   US\t+404251-0740023\tAmerica/New_York\tEastern (most areas)\n\
                   IN\t+2232+08822\tAsia/Kolkata\n\
                   AU,AQ\t-3352+15113\tAustralia/Sydney\tNew South Wales (most areas)\n\
                   XX\tnonsense\tEtc/Broken\n";
        assert!(close(zone_place(tab, "Asia/Kolkata"), (22.0 + 32.0 / 60.0, 88.0 + 22.0 / 60.0)));
        assert!(close(zone_place(tab, "Australia/Sydney"), (-(33.0 + 52.0 / 60.0), 151.0 + 13.0 / 60.0)));
        assert!(zone_place(tab, "America/New_York").is_some());
        assert_eq!(zone_place(tab, "Etc/Broken"), None);
        assert_eq!(zone_place(tab, "Europe/Nowhere"), None);
        assert_eq!(zone_place(tab, "America"), None);
    }

    #[test]
    fn a_zone_gives_its_city_else_the_googleplex() {
        let googleplex = Source::Preset("googleplex");
        assert_eq!(default_for_zone(None), googleplex);
        assert_eq!(default_for_zone(Some("Etc/UTC")), googleplex);
        assert_eq!(default_for_zone(Some("Nowhere/At_All")), googleplex);
        // The host's own table, where there is one (not on Windows).
        if std::path::Path::new("/usr/share/zoneinfo/zone.tab").exists() {
            let Source::Point { lat, lon } = default_for_zone(Some("Asia/Kolkata")) else { panic!("no Asia/Kolkata in zone.tab") };
            assert!(distance((lat, lon), (22.5726, 88.3639)) < 5000.0, "Kolkata: {lat},{lon}");
            let Source::Point { lat, lon } = default_for_zone(Some("America/Los_Angeles")) else { panic!() };
            assert!(distance((lat, lon), (34.0522, -118.2437)) < 5000.0, "Los Angeles: {lat},{lon}");
        }
    }

    #[test]
    fn a_change_wakes_a_waiter() {
        let _one = TESTS_THAT_SET.lock().unwrap_or_else(|p| p.into_inner());
        let (_, seen) = fix();
        let waiter = std::thread::spawn(move || {
            let t = Instant::now();
            wait_for_change(seen, Some(Duration::from_secs(10)));
            t.elapsed()
        });
        std::thread::sleep(Duration::from_millis(50));
        set(Source::Preset("freeway-drive"));
        assert!(waiter.join().unwrap() < Duration::from_secs(5));
        assert_eq!(current(), Source::Preset("freeway-drive"));
        let (f, changes) = fix();
        assert!(changes > seen && f.is_some_and(|f| f.speed == 28.0));
        // Nothing changes: the wait ends with its timeout.
        let t = Instant::now();
        wait_for_change(changes, Some(Duration::from_millis(20)));
        assert!(t.elapsed() >= Duration::from_millis(20));
    }

    #[test]
    fn presets_are_found_by_the_names_the_menu_shows() {
        assert_eq!(Source::parse("City Run"), Ok(Source::Preset("city-run")));
        assert_eq!(Source::parse("times square, new york"), Ok(Source::Preset("times-square")));
        assert_eq!(Source::parse("googleplex"), Ok(Source::Preset("googleplex")));
    }
}
