#!/usr/bin/env python3
"""Tests guest sockets against real servers on the host, reached through 10.0.2.2.

Runs guest/tcp.c with the ports of servers that echo, say nothing, say goodbye, reset,
count what arrives or send in pieces, and of a port nobody's on. An ANDROID_ADB_SERVER_PORT
that's really open checks the guest can't reach the adb server. Exits non-zero on failure.
"""
import os, socket, struct, subprocess, sys, threading, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sink_count = [0]
sink_done = threading.Event()


def echo(c):
    while True:
        b = c.recv(65536)
        if not b:
            return
        c.sendall(b)


def silent(c):
    # Reads nothing, for as long as the other end is there.
    time.sleep(60)


def closes(c):
    c.sendall(b"bye")


def resets(c):
    c.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))


def sink(c):
    while True:
        b = c.recv(65536)
        if not b:
            break
        sink_count[0] += len(b)
    sink_done.set()


def half_resets(c):
    # Some bytes, time for them to arrive, then a reset.
    c.sendall(b"x" * 100)
    time.sleep(0.2)
    c.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))


def pieces(c):
    c.sendall(b"a" * 1000)
    time.sleep(0.1)
    c.sendall(b"b" * 1000)


def udp_echo():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))

    def serve():
        while True:
            data, peer = s.recvfrom(65536)
            s.sendto(data, peer)

    threading.Thread(target=serve, daemon=True).start()
    return s, s.getsockname()[1]


def server(handler):
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen(16)

    def serve(c):
        try:
            handler(c)
        except OSError:
            pass
        c.close()

    def accept():
        while True:
            c, _ = s.accept()
            threading.Thread(target=serve, args=(c,), daemon=True).start()

    threading.Thread(target=accept, daemon=True).start()
    return s, s.getsockname()[1]


def free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


servers = [server(h) for h in (echo, silent, closes, resets)]
ports = [p for _, p in servers] + [free_port()]
keep_sink = server(sink)
keep_pieces = server(pieces)
keep_adb = server(echo)
keep_half = server(half_resets)
keep_udp = udp_echo()
keep_udp2 = udp_echo()
ports += [keep_sink[1], keep_pieces[1], keep_adb[1], keep_half[1], keep_udp[1], keep_udp2[1]]

env = dict(os.environ, ZEROEMU_GPU="fake", ZEROEMU_NET="1", ANDROID_ADB_SERVER_PORT=str(keep_adb[1]))
started = time.time()
guest = subprocess.Popen([f"{ROOT}/target/release/zeroemu", f"{ROOT}/target/guest/tcp_aarch64"] + [str(p) for p in ports],
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env, text=True)
threading.Timer(240, guest.kill).start()
failed = True
last = started
for line in guest.stdout:
    now = time.time()
    # A check this slow is waiting on something it shouldn't.
    note = f"  [{now - last:.1f} s]" if now - last > 1 else ""
    print(line.rstrip() + note, flush=True)
    last = now
    if line.startswith("all checks passed"):
        failed = False
guest.wait()
print(f"(the guest took {time.time() - started:.1f} s, {time.time() - last:.1f} s of it after its last line)")

sink_done.wait(30)
if sink_count[0] == 1 << 20:
    print("ok   a socket closed at once still delivered all it had queued")
else:
    print(f"FAIL the sink got {sink_count[0]} bytes")
    failed = True
sys.stdout.flush()
# Not sys.exit: daemon threads are still in their sleeps.
os._exit(1 if failed else 0)
