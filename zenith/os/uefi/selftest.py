#!/usr/bin/env python3
"""Automated QEMU self-test for the Zenith UEFI OS.

  boot (serial)  ->  shell  ->  `snake`  ->  render + motion  ->  death
  ->  `snake score=` on serial  ->  back to shell

Usage:
    ./selftest.py [path/to/zenos.iso]

Exit code 0 = every check passed.
Artifacts (serial.log, *.ppm) land next to the ISO in build/uefi/.
"""
import os
import shutil
import socket
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
ISO = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
    ROOT, "build", "uefi", "zenos.iso")
OUT = os.path.dirname(os.path.abspath(ISO))
WORK = os.environ.get("ZENITH_TEST_DIR", OUT)
SERIAL = os.path.join(WORK, "selftest-serial.log")
SOCK = os.path.join(WORK, "selftest-mon.sock")
PICS = os.path.join(WORK, "selftest")

GREEN = (0x30, 0xE0, 0x30)
DEAD = (0xFF, 0x50, 0x50)

OVMF_CANDIDATES = [
    "/usr/share/OVMF/OVMF_CODE.fd",
    "/usr/share/ovmf/OVMF.fd",
    "/usr/share/OVMF/OVMF_CODE_4M.fd",
    "/usr/share/edk2/ovmf/OVMF_CODE.fd",
    "/usr/share/edk2/x64/OVMF_CODE.fd",
]

_checks = []


def check(name, ok, detail=""):
    _checks.append((name, bool(ok)))
    mark = "PASS" if ok else "FAIL"
    print("  [%s] %s%s" % (mark, name, (" — " + detail) if detail else ""))
    return bool(ok)


# ---------------------------------------------------------------- monitor ----
class Mon:
    def __init__(self, path, timeout=15.0):
        self.s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.s.settimeout(timeout)
        err = None
        for _ in range(300):
            try:
                self.s.connect(path)
                break
            except OSError as e:
                err = e
                time.sleep(0.1)
        else:
            raise RuntimeError("monitor not reachable: %s" % err)
        self.buf = b""
        self._drain(2.0)

    def _drain(self, seconds):
        """Read until QEMU HMP prints its prompt again.

        The prompt is the lower-case ``(qemu)`` — watching for ``(QEMU)``
        never matches and used to stall every command for the full window.
        """
        deadline = time.time() + seconds
        self.s.settimeout(0.25)
        while time.time() < deadline:
            try:
                d = self.s.recv(65536)
            except socket.timeout:
                continue
            except OSError:
                break
            if not d:
                break
            self.buf += d
            if b"(qemu)" in self.buf.lower():
                return True
        return b"(qemu)" in self.buf.lower()

    def cmd(self, c, wait=0.0, timeout=30.0):
        self.buf = b""
        self.s.sendall((c + "\n").encode())
        if wait:
            time.sleep(wait)
        self._drain(timeout)
        return self.buf.decode("utf-8", "replace")

    def key(self, name, wait=0.0):
        self.cmd("sendkey " + name, wait, timeout=10.0)

    def screendump(self, path):
        if os.path.exists(path):
            os.remove(path)
        self.cmd("screendump " + path, timeout=30.0)
        # The prompt only comes back once the file is written; still, make sure
        # the size stopped changing before handing the buffer to the parser.
        last, stable = -1, 0
        for _ in range(100):
            sz = os.path.getsize(path) if os.path.exists(path) else -1
            if sz > 0 and sz == last:
                stable += 1
                if stable >= 3:
                    break
            else:
                stable = 0
            last = sz
            time.sleep(0.05)
        return os.path.exists(path) and os.path.getsize(path) > 0


# ------------------------------------------------------------- screendump ----
def read_ppm(path):
    """Return (width, height, bytes(b'\x00RRGGBB' per pixel))."""
    with open(path, "rb") as f:
        data = f.read()
    # binary P6, header: P6\n<w> <h>\n<max>\n
    if not data.startswith(b"P6"):
        raise ValueError("not a P6 ppm")
    i = 2
    fields = []
    while len(fields) < 3:
        while i < len(data) and data[i:i + 1].isspace():
            i += 1
        if data[i:i + 1] == b"#":
            while data[i:i + 1] not in (b"\n", b""):
                i += 1
            continue
        start = i
        while i < len(data) and not data[i:i + 1].isspace():
            i += 1
        fields.append(int(data[start:i]))
    i += 1  # single whitespace after maxval
    w, h, _mx = fields
    return w, h, data[i:i + w * h * 3]


# Only the top-left 1024x768 is ever painted by the GOP; scanning the whole
# 2048x2048 backing surface in Python would be needlessly slow.
SCAN_W, SCAN_H = 1024, 768


def _aligned_hits(row, pat):
    """Byte offsets in `row` where `pat` matches AND starts on a pixel boundary.

    A raw ``bytes.find`` also reports (224,48,48) inside (48,224,48)'s own
    bytes, so matches at offset % 3 != 0 are skipped.
    """
    out = []
    i = 0
    while True:
        k = row.find(pat, i)
        if k < 0:
            break
        if k % 3 == 0:
            out.append(k)
            i = k + 3
        else:
            i = k + 1
    return out


def count_color(rgb, px, w, h=SCAN_H):
    """Exact, pixel-aligned match count (framebuffer colours are verbatim)."""
    pat = bytes(rgb)
    rows = min(h, len(px) // (w * 3)) if w else 0
    n = 0
    for y in range(rows):
        base = y * w * 3
        n += len(_aligned_hits(px[base:base + w * 3], pat))
    return n


def green_positions(rgb, px, w, h=SCAN_H):
    """Bounding box (x0,y0,x1,y1,n) of all pixels equal to rgb, or None."""
    pat = bytes(rgb)
    rows = min(h, len(px) // (w * 3)) if w else 0
    x0 = y0 = 1 << 30
    x1 = y1 = -1
    n = 0
    for y in range(rows):
        base = y * w * 3
        for off in _aligned_hits(px[base:base + w * 3], pat):
            x = off // 3
            n += 1
            if x < x0:
                x0 = x
            if x > x1:
                x1 = x
            if y < y0:
                y0 = y
            if y > y1:
                y1 = y
    if n == 0:
        return None
    return (x0, y0, x1, y1, n)


# ------------------------------------------------------------------ qemu -----
def kill_qemu():
    # -x matches on the executable name only, so our own shell argv never
    # matches (the `pkill -f` flavour does and kills this script's shell).
    subprocess.call(["pkill", "-x", "qemu-system-x86_64"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.5)


def serial_text():
    try:
        with open(SERIAL, "rb") as f:
            return f.read().decode("utf-8", "replace")
    except FileNotFoundError:
        return ""


def wait_serial(needle, timeout=30.0):
    t0 = time.time()
    while time.time() - t0 < timeout:
        if needle in serial_text():
            return True
        time.sleep(0.2)
    return False


def wait_serial_since(start, needle, timeout=30.0):
    """Like wait_serial but only looks at output produced after `start`."""
    t0 = time.time()
    while time.time() - t0 < timeout:
        if needle in serial_text()[start:]:
            return True
        time.sleep(0.1)
    return False


def type_word(mon, word, delay=0.07):
    for ch in word:
        mon.key(ch, delay)


def main():
    if not os.path.isfile(ISO):
        print("no image: %s (run build.sh first)" % ISO)
        return 2

    ovmf = next((c for c in OVMF_CANDIDATES if os.path.isfile(c)), None)
    if not ovmf:
        print("OVMF firmware not found")
        return 2

    os.makedirs(WORK, exist_ok=True)
    kill_qemu()
    for p in (SERIAL, SOCK):
        if os.path.exists(p):
            os.remove(p)
    for f in os.listdir(WORK):
        if f.startswith("selftest") and f.endswith(".ppm"):
            os.remove(os.path.join(WORK, f))

    print("zenith uefi selftest")
    print("  iso : %s" % ISO)
    print("  ovmf: %s" % ovmf)

    qemu = subprocess.Popen(
        ["qemu-system-x86_64",
         "-machine", "q35", "-m", "512", "-cpu", "qemu64",
         "-bios", ovmf,
         "-drive", "if=ide,media=cdrom,file=%s,format=raw,readonly=on" % ISO,
         "-display", "none", "-vga", "std",
         "-serial", "file:" + SERIAL,
         "-monitor", "unix:%s,server,nowait" % SOCK,
         "-no-reboot", "-no-shutdown"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    try:
        # ---- 1. firmware + boot stub + OS up -------------------------------
        check("UEFI stub reaches ExitBootServices ([Z4])",
              wait_serial("[Z4]", 40))
        check("OS main() starts (ZENITH OS MVP)", wait_serial("ZENITH OS MVP", 15))
        check("IDT/PIC/PIT/keyboard init",
              wait_serial("IDT PIC PIT KBD ok", 15) and wait_serial("STI done", 15))
        check("no fault/trap on boot", "FAULT" not in serial_text()
              and "halted on exception" not in serial_text())

        mon = Mon(SOCK)
        time.sleep(1.0)

        # ---- 2. shell prompt renders --------------------------------------
        shot = PICS + "-01-boot.ppm"
        ok = mon.screendump(shot)
        w, h, px = read_ppm(shot) if ok else (0, 0, b"")
        # banner title colour 0x55FFFF
        check("banner drawn on screen",
              ok and count_color((0x55, 0xFF, 0xFF), px, w) > 100,
              "%d title px" % count_color((0x55, 0xFF, 0xFF), px, w) if ok else "no dump")

        # ---- 3. start the game --------------------------------------------
        mark = len(serial_text())
        type_word(mon, "snake", 0.04)
        mon.key("ret", 0.05)

        shot = PICS + "-02-snake.ppm"
        mon.screendump(shot)
        w, h, px = read_ppm(shot)
        box = green_positions(GREEN, px, w)
        check("snake renders green cells", box is not None,
              "n=%d bbox=%s" % (box[4], box[:4]) if box else "no green pixels")

        # ---- 4. it actually moves (70 ms per step, so keep this tight) -----
        shot2 = PICS + "-03-snake2.ppm"
        time.sleep(0.25)
        mon.screendump(shot2)
        w2, h2, px2 = read_ppm(shot2)
        box2 = green_positions(GREEN, px2, w2)
        check("snake moves between dumps",
              box is not None and box2 is not None and box[:4] != box2[:4],
              "bbox %s -> %s" % (box[:4] if box else None,
                                 box2[:4] if box2 else None))

        # ---- 5. it runs into the right-hand wall by itself ----------------
        died = wait_serial_since(mark, "snake score=", 15)
        check("snake reports death on serial (snake score=)", died)

        shot = PICS + "-04-dead.ppm"
        mon.screendump(shot)
        w, h, px = read_ppm(shot)
        n_dead = count_color(DEAD, px, w)
        check("GAME OVER banner drawn", n_dead > 50, "%d px" % n_dead)

        # ---- 6. any key returns to the shell ------------------------------
        mon.key("esc", 0.05)
        shot = PICS + "-05-shell.ppm"
        mon.screendump(shot)
        w, h, px = read_ppm(shot)
        n_title = count_color((0x55, 0xFF, 0xFF), px, w)
        check("returns to shell banner", n_title > 100, "%d title px" % n_title)

        type_word(mon, "help", 0.04)
        mon.key("ret", 0.05)
        shot = PICS + "-06-help.ppm"
        mon.screendump(shot)
        w, h, px = read_ppm(shot)
        n_text = count_color((0xE0, 0xE0, 0xE0), px, w)
        check("`help` renders a non-empty screen", n_text > 300,
              "%d text px" % n_text)

        check("no exception during the whole run",
              "halted on exception" not in serial_text()
              and "FAULT" not in serial_text())

    finally:
        kill_qemu()

    failed = [n for n, ok in _checks if not ok]
    print("\n%d/%d checks passed" % (len(_checks) - len(failed), len(_checks)))
    if failed:
        print("failed: " + ", ".join(failed))
        print("serial: " + SERIAL)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
