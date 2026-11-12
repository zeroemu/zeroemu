#!/usr/bin/env python3
"""Tests zeroemu's host connections, which adb uses, from the host side.

Runs guest/vsock.c with a host port, and checks what arrives at this end: it connects
before the guest listens, pushes 4 MiB through an echo with a slow reader, half-closes,
and sees a close from the guest. Exits non-zero on failure.
"""
import hashlib, os, socket, subprocess, sys, threading, time

# A port nothing else knows of, and no telling a real adb server about it: it would
# connect at once, and keep trying that port for a minute after this.
with socket.socket() as probe:
    probe.bind(("127.0.0.1", 0))
    PORT = probe.getsockname()[1]
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENV = dict(os.environ, ZEROEMU_GPU="fake", ANDROID_ADB_SERVER_PORT="1")
guest = subprocess.Popen(
    [f"{ROOT}/target/release/zeroemu", "--adb-port", str(PORT), f"{ROOT}/target/guest/vsock_aarch64"],
    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=ENV, text=True)
failures = []


def check(cond, name):
    print(("ok   " if cond else "FAIL ") + name)
    if not cond:
        failures.append(name)


def connect():
    for _ in range(100):
        try:
            return socket.create_connection(("127.0.0.1", PORT), timeout=30)
        except OSError:
            time.sleep(0.05)
    raise SystemExit("could not connect")


data = os.urandom(4 * 1024 * 1024)
s = connect()
got = hashlib.sha256()
count = [0]


def reader():
    # Slowly at first, so the guest fills every queue and has to wait.
    time.sleep(0.5)
    while True:
        b = s.recv(65536)
        if not b:
            return
        got.update(b)
        count[0] += len(b)


r = threading.Thread(target=reader)
r.start()
s.sendall(data)
s.shutdown(socket.SHUT_WR)
r.join(60)
check(not r.is_alive() and count[0] == len(data), f"the echo ended at {count[0]} bytes")
check(got.hexdigest() == hashlib.sha256(data).hexdigest(), "and matches what was sent")
s.close()

s = connect()
time.sleep(0.3)  # the guest is in its blocking read until its alarm
s.sendall(b"hello")
b = b""
while True:
    part = s.recv(16)
    if not part:
        break
    b += part
check(b == b"bye", "the guest's reply, then the end when it closes")
s.close()

out, _ = guest.communicate(timeout=30)
sys.stdout.write(out)
check(guest.returncode == 0, f"the guest exited {guest.returncode}")
if failures or "all checks passed" not in out:
    print("FAILED")
    sys.exit(1)
print("all host connection checks passed")
