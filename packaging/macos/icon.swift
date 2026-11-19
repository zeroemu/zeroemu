// zeroemu's app icon: a "0" that is also the outline of a phone, with a home bar inside,
// on a squircle laid out on Apple's 1024 icon grid (an 824 body with 100 around it).
// Drawn in code so it can be changed and redrawn; scripts/make-icon.sh turns the PNG
// this writes into packaging/macos/zeroemu.icns.
// Run: swift packaging/macos/icon.swift out.png
import AppKit
import CoreGraphics
import Foundation

let S: CGFloat = 1024
let cs = CGColorSpace(name: CGColorSpace.sRGB)!

func rgb(_ hex: UInt32, _ a: CGFloat = 1) -> CGColor {
    CGColor(srgbRed: CGFloat((hex >> 16) & 0xff) / 255,
            green: CGFloat((hex >> 8) & 0xff) / 255,
            blue: CGFloat(hex & 0xff) / 255, alpha: a)
}
func white(_ a: CGFloat) -> CGColor { CGColor(srgbRed: 1, green: 1, blue: 1, alpha: a) }
func black(_ a: CGFloat) -> CGColor { CGColor(srgbRed: 0, green: 0, blue: 0, alpha: a) }
func gradient(_ stops: [(CGFloat, CGColor)]) -> CGGradient {
    CGGradient(colorsSpace: cs, colors: stops.map { $0.1 } as CFArray, locations: stops.map { $0.0 })!
}

// Apple-style continuous-corner rounded rect (top-left origin, clockwise).
func continuousRect(_ r: CGRect, radius: CGFloat) -> CGPath {
    let k: CGFloat = 1.52866483
    let rad = min(radius, min(r.width, r.height) / 2 / k)
    // One corner, in local (back-along-incoming-edge, along-outgoing-edge) units.
    let seg: [(CGPoint, CGPoint?, CGPoint?)] = [
        (CGPoint(x: 0.66993427, y: 0.06549600), CGPoint(x: 1.08849323, y: 0), CGPoint(x: 0.86840689, y: 0)),
        (CGPoint(x: 0.63149399, y: 0.07491100), nil, nil),
        (CGPoint(x: 0.07491100, y: 0.63149399), CGPoint(x: 0.37282392, y: 0.16905899), CGPoint(x: 0.16905899, y: 0.37282392)),
        (CGPoint(x: 0.06549600, y: 0.66993427), nil, nil),
        (CGPoint(x: 0, y: k), CGPoint(x: 0, y: 0.86840689), CGPoint(x: 0, y: 1.08849323)),
    ]
    let corners: [(CGPoint, CGVector, CGVector)] = [
        (CGPoint(x: r.maxX, y: r.minY), CGVector(dx: 1, dy: 0), CGVector(dx: 0, dy: 1)),
        (CGPoint(x: r.maxX, y: r.maxY), CGVector(dx: 0, dy: 1), CGVector(dx: -1, dy: 0)),
        (CGPoint(x: r.minX, y: r.maxY), CGVector(dx: -1, dy: 0), CGVector(dx: 0, dy: -1)),
        (CGPoint(x: r.minX, y: r.minY), CGVector(dx: 0, dy: -1), CGVector(dx: 1, dy: 0)),
    ]
    let p = CGMutablePath()
    for (i, (c, d1, d2)) in corners.enumerated() {
        func m(_ q: CGPoint) -> CGPoint {
            CGPoint(x: c.x - q.x * rad * d1.dx + q.y * rad * d2.dx,
                    y: c.y - q.x * rad * d1.dy + q.y * rad * d2.dy)
        }
        let start = m(CGPoint(x: k, y: 0))
        if i == 0 { p.move(to: start) } else { p.addLine(to: start) }
        for (to, c1, c2) in seg {
            if let c1 = c1, let c2 = c2 { p.addCurve(to: m(to), control1: m(c1), control2: m(c2)) }
            else { p.addLine(to: m(to)) }
        }
    }
    p.closeSubpath()
    return p
}

// Superellipse |x/a|^n + |y/b|^n = 1, finely sampled.
func superellipsePoints(center c: CGPoint, a: CGFloat, b: CGFloat, n: CGFloat, steps: Int = 8192) -> [CGPoint] {
    (0..<steps).map { i in
        let t = CGFloat(i) / CGFloat(steps) * 2 * .pi
        let ct = cos(t), st = sin(t)
        return CGPoint(x: c.x + a * copysign(pow(abs(ct), 2 / n), ct),
                       y: c.y + b * copysign(pow(abs(st), 2 / n), st))
    }
}

// The curve moved by d along its outward normal (d < 0 moves inward): an exact constant-width offset.
func offset(_ pts: [CGPoint], center c: CGPoint, by d: CGFloat) -> [CGPoint] {
    let n = pts.count
    return (0..<n).map { i in
        let p = pts[i], a = pts[(i + n - 1) % n], b = pts[(i + 1) % n]
        var nx = b.y - a.y, ny = -(b.x - a.x)
        let len = max(hypot(nx, ny), 1e-9)
        nx /= len; ny /= len
        if nx * (p.x - c.x) + ny * (p.y - c.y) < 0 { nx = -nx; ny = -ny }
        return CGPoint(x: p.x + nx * d, y: p.y + ny * d)
    }
}

func polygon(_ pts: [CGPoint]) -> CGPath {
    let p = CGMutablePath()
    p.addLines(between: pts)
    p.closeSubpath()
    return p
}

func stadium(_ r: CGRect) -> CGPath {
    CGPath(roundedRect: r, cornerWidth: r.height / 2, cornerHeight: r.height / 2, transform: nil)
}

// ---------------------------------------------------------------- design
// Palette: deep ink squircle, one mint accent. The top is light enough, with the rim
// below, that the icon keeps its edge in a dark Dock.
let bgTop = rgb(0x44599C), bgBottom = rgb(0x0D1430)
let ringTop = rgb(0x86FAD8), ringMid = rgb(0x3EE3B4), ringBottom = rgb(0x0FB98B)
let screenTop = rgb(0x1A2447), screenBottom = rgb(0x10172F)
let accent = rgb(0x4BEBC0)

// Geometry (top-left coordinates on the 1024 canvas).
let center = CGPoint(x: 512, y: 506)
let A: CGFloat = 145, B: CGFloat = 230, N: CGFloat = 3.4, T: CGFloat = 94   // half-width, half-height, squareness, stroke

// ---------------------------------------------------------------- canvas
let ctx = CGContext(data: nil, width: Int(S), height: Int(S), bitsPerComponent: 8, bytesPerRow: 0,
                    space: cs, bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
ctx.translateBy(x: 0, y: S)
ctx.scaleBy(x: 1, y: -1)           // work in top-left coordinates
ctx.setShouldAntialias(true)
ctx.interpolationQuality = .high

// Shadow offsets are in device space, so a negative height casts downward.
func down(_ d: CGFloat) -> CGSize { CGSize(width: 0, height: -d) }
let huge = CGRect(x: -2000, y: -2000, width: 5000, height: 5000)

// Inner shadow / inner highlight of a shape: only the shadow of the outside lands inside.
func innerShadow(_ shape: CGPath, offset: CGSize, blur: CGFloat, color: CGColor) {
    ctx.saveGState()
    ctx.addPath(shape)
    ctx.clip(using: .evenOdd)
    ctx.setShadow(offset: offset, blur: blur, color: color)
    ctx.addRect(huge)
    ctx.addPath(shape)
    ctx.setFillColor(black(1))
    ctx.fillPath(using: .evenOdd)
    ctx.restoreGState()
}

let body = CGRect(x: 100, y: 100, width: 824, height: 824)
let bodyPath = continuousRect(body, radius: 185.4)

// Drop shadow under the body, as in Apple's icon template.
ctx.saveGState()
ctx.setShadow(offset: down(10), blur: 22, color: black(0.30))
ctx.addPath(bodyPath)
ctx.setFillColor(bgBottom)
ctx.fillPath()
ctx.restoreGState()

// Body fill: vertical gradient plus a soft light from above.
ctx.saveGState()
ctx.addPath(bodyPath)
ctx.clip()
ctx.drawLinearGradient(gradient([(0, bgTop), (1, bgBottom)]),
                       start: CGPoint(x: 512, y: body.minY), end: CGPoint(x: 512, y: body.maxY), options: [])
ctx.drawRadialGradient(gradient([(0, white(0.10)), (1, white(0))]),
                       startCenter: CGPoint(x: 512, y: 120), startRadius: 0,
                       endCenter: CGPoint(x: 512, y: 120), endRadius: 640, options: [])

// ---------------------------------------------------------------- the zero
let centerline = superellipsePoints(center: center, a: A, b: B, n: N)
let outer = polygon(offset(centerline, center: center, by: T / 2))
let hole = polygon(offset(centerline, center: center, by: -T / 2))
let ring = CGMutablePath()
ring.addPath(outer)
ring.addPath(hole)
let holeTop = center.y - B + T / 2, holeBottom = center.y + B - T / 2

// Screen inside the zero: dark glass, faintly lit from the home bar, recessed under the ring.
ctx.saveGState()
ctx.addPath(hole)
ctx.clip()
ctx.drawLinearGradient(gradient([(0, screenTop), (1, screenBottom)]),
                       start: CGPoint(x: 512, y: holeTop), end: CGPoint(x: 512, y: holeBottom), options: [])
ctx.drawRadialGradient(gradient([(0, accent.copy(alpha: 0.16)!), (1, accent.copy(alpha: 0)!)]),
                       startCenter: CGPoint(x: 512, y: holeBottom - 30), startRadius: 0,
                       endCenter: CGPoint(x: 512, y: holeBottom - 30), endRadius: 230, options: [])
// Faint glass sheen across the upper screen.
let sheen: CGFloat = 0.06
do {
    let sh = CGMutablePath()
    sh.move(to: CGPoint(x: 300, y: holeTop - 10))
    sh.addLine(to: CGPoint(x: 724, y: holeTop - 10))
    sh.addLine(to: CGPoint(x: 724, y: holeTop + 40))
    sh.addLine(to: CGPoint(x: 300, y: holeTop + 230))
    sh.closeSubpath()
    ctx.addPath(sh)
    ctx.clip()
    ctx.drawLinearGradient(gradient([(0, white(sheen)), (1, white(sheen * 0.2))]),
                           start: CGPoint(x: 512, y: holeTop), end: CGPoint(x: 512, y: holeTop + 230), options: [])
}
ctx.restoreGState()
innerShadow(hole, offset: down(10), blur: 22, color: black(0.55))

// Ring, with a soft cast shadow (drawn in a layer so the shadow follows the shape).
ctx.saveGState()
ctx.setShadow(offset: down(12), blur: 28, color: black(0.45))
ctx.beginTransparencyLayer(auxiliaryInfo: nil)
ctx.addPath(ring)
ctx.clip(using: .evenOdd)
ctx.drawLinearGradient(gradient([(0, ringTop), (0.45, ringMid), (1, ringBottom)]),
                       start: CGPoint(x: 512, y: center.y - B - T / 2), end: CGPoint(x: 512, y: center.y + B + T / 2),
                       options: [])
ctx.endTransparencyLayer()
ctx.restoreGState()
// Glass edge: light catches the upward-facing edges, the downward ones darken a touch.
innerShadow(ring, offset: down(5), blur: 6, color: white(0.55))
innerShadow(ring, offset: down(-6), blur: 10, color: rgb(0x05543F, 0.35))

// Home bar, softly glowing.
let barW: CGFloat = 92, barH: CGFloat = 22
let barRect = CGRect(x: 512 - barW / 2, y: holeBottom - 42 - barH, width: barW, height: barH)
ctx.saveGState()
ctx.setShadow(offset: .zero, blur: 18, color: accent.copy(alpha: 0.7)!)
ctx.addPath(stadium(barRect))
ctx.setFillColor(accent)
ctx.fillPath()
ctx.restoreGState()

// Glass rim of the body: a fine light edge, brightest at the top.
ctx.saveGState()
ctx.addPath(bodyPath.copy(strokingWithWidth: 5, lineCap: .butt, lineJoin: .round, miterLimit: 10))
ctx.clip()
ctx.drawLinearGradient(gradient([(0, white(0.55)), (0.35, white(0.08)), (1, white(0.14))]),
                       start: CGPoint(x: 512, y: body.minY), end: CGPoint(x: 512, y: body.maxY), options: [])
ctx.restoreGState()

ctx.restoreGState() // body clip

// ---------------------------------------------------------------- write
let args = CommandLine.arguments
guard args.count == 2 else { print("usage: swift icon.swift out.png"); exit(2) }
let out = URL(fileURLWithPath: args[1])
let rep = NSBitmapImageRep(cgImage: ctx.makeImage()!)
rep.size = NSSize(width: S, height: S)
try! rep.representation(using: .png, properties: [:])!.write(to: out)
print("wrote \(out.path)")
