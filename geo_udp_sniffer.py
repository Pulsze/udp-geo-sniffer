#!/usr/bin/env python3
"""UDP Geo Sniffer - overlay kanan atas (Linux / GNOME).

Menampilkan paket UDP dengan source IP publik beserta kota & negara dari
database MaxMind GeoLite2 yang dipakai Wireshark. Capture memakai
tshark/dumpcap, jadi TIDAK perlu menjalankan skrip ini sebagai root
(asalkan user ada di grup "wireshark" atau dumpcap punya capability).

Pemakaian:
  ./geo_udp_sniffer.py                 -> overlay di pojok kanan atas
  ./geo_udp_sniffer.py --console       -> tampil di terminal saja
  ./geo_udp_sniffer.py --unique        -> tiap source IP hanya ditampilkan sekali
  ./geo_udp_sniffer.py --demo          -> data contoh untuk uji tampilan
  ./geo_udp_sniffer.py --interface enp7s0 --filter "udp"

Opsi lain:
  --monitor N   monitor yang dipakai (default 0)
  --margin N    jarak dari tepi layar (default 20 px)
  --width N     lebar overlay (default 620 px)
  --height N    tinggi overlay (default 390 px)

Ctrl+C di terminal (atau tombol x di overlay) untuk berhenti.
"""

from __future__ import annotations

import argparse
import functools
import ipaddress
import os
import queue
import shutil
import signal
import subprocess
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass
from xml.sax.saxutils import escape

APP_NAME = "UDP Geo Sniffer"

# Paksa XWayland supaya window bisa diposisikan di kanan atas dan selalu
# di atas. Di Wayland murni, compositor yang menentukan posisi window.
os.environ.setdefault("GDK_BACKEND", "x11")

# Urutan field HARUS sama dengan urutan -e di bawah.
TSHARK_FIELDS = (
    "frame.time_epoch",
    "ip.src",
    "ipv6.src",
    "udp.srcport",
    "ip.geoip.src_city",
    "ipv6.geoip.src_city",
    "ip.geoip.src_country",
    "ipv6.geoip.src_country",
    "ip.geoip.src_country_iso",
    "ipv6.geoip.src_country_iso",
)

CITY_DB_CANDIDATES = (
    os.path.expanduser("~/.local/share/wireshark/maxmind/GeoLite2-City.mmdb"),
    "/usr/share/GeoIP/GeoLite2-City.mmdb",
    "/usr/share/wireshark/maxmind/GeoLite2-City.mmdb",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "GeoLite2-City.mmdb"),
)

COLOR_RED = "\033[91m" if sys.stdout.isatty() else ""
COLOR_RESET = "\033[0m" if sys.stdout.isatty() else ""


# --------------------------------------------------------------------------- data
@dataclass
class Packet:
    number: int
    ts: float
    src: str
    sport: str
    city: str
    country: str
    iso: str

    @property
    def city_text(self) -> str:
        return self.city or "Unknown City"

    @property
    def country_text(self) -> str:
        return self.country or "Unknown Country"

    @property
    def iso_text(self) -> str:
        return self.iso or "??"


@functools.lru_cache(maxsize=8192)
def is_public(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def find_city_db() -> str | None:
    for path in CITY_DB_CANDIDATES:
        if os.path.isfile(path):
            return path
    return None


# ----------------------------------------------------------------------- capture
class Capture(threading.Thread):
    """Menjalankan tshark dan mengubah baris output menjadi objek Packet."""

    def __init__(self, out_queue: "queue.Queue[Packet]", interface: str,
                 bpf_filter: str, unique: bool):
        super().__init__(daemon=True, name="tshark-capture")
        self.out_queue = out_queue
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.unique = unique
        self.count = 0
        self.seen: set[str] = set()
        self.proc: subprocess.Popen | None = None
        self.stop_event = threading.Event()
        self._lock = threading.Lock()
        self._status = "Menyiapkan tshark..."
        self._error = False

    # -- status dibaca GUI dari thread lain
    @property
    def status(self) -> tuple[str, bool]:
        with self._lock:
            return self._status, self._error

    def set_status(self, text: str, error: bool = False) -> None:
        with self._lock:
            self._status = text
            self._error = error

    def run(self) -> None:
        tshark = shutil.which("tshark")
        if not tshark:
            self.set_status("tshark tidak ditemukan. Install paket wireshark-cli.", True)
            return

        cmd = [
            tshark,
            "-l",                                   # line-buffered
            "-i", self.interface,
            "-f", self.bpf_filter,
            "-o", "nameres.network_name:FALSE",     # IP tetap numerik
            "-o", "nameres.mac_name:FALSE",
            "-o", "nameres.maxmind_geoip:TRUE",
            "-T", "fields",
            "-E", "separator=/t",
            "-E", "occurrence=f",
            "-E", "quote=n",
        ]
        for field in TSHARK_FIELDS:
            cmd.extend(("-e", field))

        try:
            self.proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                errors="replace",
                start_new_session=True,
            )
        except OSError as exc:
            self.set_status(f"Gagal menjalankan tshark: {exc}", True)
            return

        threading.Thread(target=self._read_stderr, daemon=True,
                         name="tshark-stderr").start()
        self.set_status(f"Mendengarkan UDP publik di {self.interface}...")

        assert self.proc.stdout is not None
        for line in self.proc.stdout:
            if self.stop_event.is_set():
                break
            self._handle_line(line)

        rc = self.proc.wait()
        if not self.stop_event.is_set():
            _text, already_error = self.status
            if rc != 0 and not already_error:
                self.set_status(f"tshark berhenti (kode {rc}).", True)
            elif not already_error:
                self.set_status("tshark berhenti.", True)
        else:
            self.set_status("Dihentikan.")

    def _read_stderr(self) -> None:
        assert self.proc is not None and self.proc.stderr is not None
        for raw in self.proc.stderr:
            line = raw.strip()
            if not line:
                continue
            low = line.lower()
            if "promiscuous mode is not supported" in low:
                continue  # normal untuk interface "any"
            if "capturing on" in low:
                self.set_status(f"Mendengarkan UDP publik di {self.interface}...")
            elif any(word in low for word in
                     ("permission", "don't have", "not found", "error",
                      "failed", "invalid", "couldn't", "could not",
                      "no such device", "no device", "cannot")):
                self.set_status(f"tshark: {line}", True)

    def _handle_line(self, line: str) -> None:
        parts = line.rstrip("\n").split("\t")
        if len(parts) < len(TSHARK_FIELDS):
            return

        src = parts[1].strip() or parts[2].strip()
        if not src or not is_public(src):
            return
        if self.unique:
            if src in self.seen:
                return
            self.seen.add(src)

        try:
            ts = float(parts[0])
        except (TypeError, ValueError):
            ts = time.time()

        city = parts[4].strip() or parts[5].strip()
        country = parts[6].strip() or parts[7].strip()
        iso = parts[8].strip() or parts[9].strip()

        self.count += 1
        try:
            self.out_queue.put_nowait(Packet(
                number=self.count,
                ts=ts,
                src=src,
                sport=parts[3].strip() or "?",
                city=city,
                country=country,
                iso=iso,
            ))
        except queue.Full:
            pass

    def stop(self) -> None:
        self.stop_event.set()
        proc = self.proc
        if proc is None or proc.poll() is not None:
            return
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except (ProcessLookupError, PermissionError, OSError):
            try:
                proc.terminate()
            except OSError:
                pass
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                proc.kill()


class DemoCapture(threading.Thread):
    """Data contoh supaya overlay bisa dicoba tanpa lalu lintas jaringan."""

    SAMPLES = (
        ("114.122.0.1", "443", "Medan", "Indonesia", "ID"),
        ("110.136.0.1", "3478", "Jakarta", "Indonesia", "ID"),
        ("203.194.0.1", "443", "Perth", "Australia", "AU"),
        ("202.80.0.1", "19302", "", "Hong Kong", "HK"),
        ("74.125.200.94", "443", "", "United States", "US"),
        ("103.10.0.1", "53", "Guangzhou", "China", "CN"),
    )

    def __init__(self, out_queue: "queue.Queue[Packet]"):
        super().__init__(daemon=True, name="demo-capture")
        self.out_queue = out_queue
        self.stop_event = threading.Event()
        self.count = 0
        self._lock = threading.Lock()
        self._status = "Mode demo - data contoh (bukan capture asli)."

    @property
    def status(self) -> tuple[str, bool]:
        with self._lock:
            return self._status, False

    def run(self) -> None:
        index = 0
        while not self.stop_event.wait(0.9):
            src, sport, city, country, iso = self.SAMPLES[index % len(self.SAMPLES)]
            index += 1
            self.count += 1
            try:
                self.out_queue.put_nowait(Packet(
                    number=self.count,
                    ts=time.time(),
                    src=src,
                    sport=sport,
                    city=city,
                    country=country,
                    iso=iso,
                ))
            except queue.Full:
                pass

    def stop(self) -> None:
        self.stop_event.set()


# ------------------------------------------------------------------------ console
def run_console(out_queue: "queue.Queue[Packet]", capture) -> None:
    print("=" * 74)
    print(f"  {APP_NAME} - Real-Time (City + Country)")
    print("=" * 74)
    print(f"  {capture.status[0]}")
    if find_city_db() is None:
        print("  PERINGATAN: GeoLite2-City.mmdb tidak ditemukan.")
    print("  Tekan Ctrl+C untuk berhenti.\n")

    try:
        while capture.is_alive() or not out_queue.empty():
            try:
                packet = out_queue.get(timeout=0.3)
            except queue.Empty:
                continue
            stamp = time.strftime("%H:%M:%S", time.localtime(packet.ts))
            print(
                f"{stamp}  #{packet.number} [UDP] {packet.src}:{packet.sport} | "
                f"City: {COLOR_RED}{packet.city_text}{COLOR_RESET} | "
                f"Country: {packet.country_text} ({packet.iso_text})",
                flush=True,
            )
    except KeyboardInterrupt:
        print("\nDihentikan oleh pengguna.")
    finally:
        capture.stop()
        try:
            capture.join(timeout=3)
        except RuntimeError:
            pass
        text, is_error = capture.status
        if is_error:
            print(f"\n{text}")


# --------------------------------------------------------------------------- GUI
def run_overlay(out_queue: "queue.Queue[Packet]", capture, args) -> None:
    try:
        import gi
        gi.require_version("Gdk", "3.0")
        gi.require_version("Gtk", "3.0")
        from gi.repository import Gdk, GLib, Gtk, Pango
    except Exception as exc:  # GTK tidak tersedia
        print(f"GTK3 tidak tersedia ({exc}); memakai mode console.")
        run_console(out_queue, capture)
        return

    init = Gtk.init_check([])
    if isinstance(init, tuple):
        init = init[0]
    if not init:
        print("Tidak bisa membuka display; memakai mode console.")
        run_console(out_queue, capture)
        return

    width, height = args.width, args.height
    margin = args.margin
    max_rows = max(6, args.rows)

    css = b"""
    window.overlay {
        background-color: #0b1017;
        border: 1px solid rgba(88, 166, 255, 0.45);
        border-radius: 14px;
    }
    label { color: #e6edf3; }
    label.title { font-weight: 700; font-size: 13px; letter-spacing: 1px; }
    label.subtitle { color: #8b949e; font-size: 10px; }
    label.counter {
        color: #58a6ff;
        background-color: rgba(56, 139, 253, 0.14);
        border-radius: 9px;
        padding: 2px 9px;
        font-size: 10px;
        font-weight: 700;
    }
    label.dot { color: #3fb950; font-size: 10px; }
    label.dot.error { color: #f85149; }
    label.status { color: #8b949e; font-size: 10px; }
    label.packet { font-family: monospace; font-size: 10.5px; }
    button.close {
        background: transparent;
        border: none;
        box-shadow: none;
        color: #8b949e;
        padding: 0 4px;
        min-width: 20px;
        min-height: 20px;
        font-size: 14px;
    }
    button.close:hover { color: #f85149; }
    separator { background-color: rgba(255, 255, 255, 0.08); }
    """

    provider = Gtk.CssProvider()
    provider.load_from_data(css)
    Gtk.StyleContext.add_provider_for_screen(
        Gdk.Screen.get_default(), provider,
        Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION,
    )

    window = Gtk.Window(type=Gtk.WindowType.TOPLEVEL)
    window.set_title(APP_NAME)
    window.get_style_context().add_class("overlay")
    window.set_decorated(False)
    window.set_resizable(False)
    window.set_keep_above(True)
    window.set_skip_taskbar_hint(True)
    window.set_skip_pager_hint(True)
    window.set_accept_focus(False)
    window.set_focus_on_map(False)
    window.set_default_size(width, height)

    outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
    window.add(outer)

    # ---- header
    header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
    header.set_border_width(14)
    title_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=1)
    title = Gtk.Label(label="UDP GEO SNIFFER", xalign=0)
    title.get_style_context().add_class("title")
    subtitle_text = "GeoLite2 - real-time - terbaru di atas"
    if find_city_db() is None:
        subtitle_text = "DB GeoLite2-City.mmdb tidak ditemukan - kota kosong"
    subtitle = Gtk.Label(label=subtitle_text, xalign=0)
    subtitle.get_style_context().add_class("subtitle")
    title_box.pack_start(title, False, False, 0)
    title_box.pack_start(subtitle, False, False, 0)

    counter = Gtk.Label(label="0 pkt")
    counter.get_style_context().add_class("counter")

    close_button = Gtk.Button(label="\u2715")
    close_button.get_style_context().add_class("close")
    close_button.set_relief(Gtk.ReliefStyle.NONE)
    close_button.set_tooltip_text("Tutup")
    close_button.connect("clicked", lambda *_: window.close())

    header.pack_start(counter, False, False, 0)
    header.pack_start(close_button, False, False, 0)

    # Area drag hanya di judul, supaya tombol x tetap bisa diklik.
    drag_area = Gtk.EventBox()
    drag_area.set_visible_window(False)
    drag_area.add_events(Gdk.EventMask.BUTTON_PRESS_MASK)
    drag_area.add(title_box)
    header.pack_start(drag_area, True, True, 0)
    header.reorder_child(drag_area, 0)

    outer.pack_start(header, False, False, 0)
    outer.pack_start(Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL),
                     False, False, 0)

    # ---- status
    status_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
    status_row.set_border_width(10)
    status_row.set_margin_start(4)
    dot = Gtk.Label(label="\u25cf")
    dot.get_style_context().add_class("dot")
    status = Gtk.Label(label=capture.status[0], xalign=0)
    status.get_style_context().add_class("status")
    status.set_ellipsize(Pango.EllipsizeMode.END)
    status_row.pack_start(dot, False, False, 0)
    status_row.pack_start(status, True, True, 0)
    outer.pack_start(status_row, False, False, 0)

    # ---- daftar paket
    log_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=3)
    log_box.set_border_width(14)
    log_box.set_margin_top(0)
    row_labels: list[Gtk.Label] = []
    for _ in range(max_rows):
        label = Gtk.Label(label="", xalign=0)
        label.get_style_context().add_class("packet")
        label.set_use_markup(True)
        label.set_ellipsize(Pango.EllipsizeMode.END)
        log_box.pack_start(label, False, False, 0)
        row_labels.append(label)
    outer.pack_start(log_box, True, True, 0)

    # ---- drag window lewat header
    def start_drag(_widget, event):
        if event.button == 1:
            window.begin_move_drag(event.button, int(event.x_root), int(event.y_root), event.time)
            return True
        return False

    drag_area.connect("button-press-event", start_drag)

    packets: deque[Packet] = deque(maxlen=max_rows)

    def render() -> None:
        for label, packet in zip(row_labels, reversed(packets)):
            stamp = time.strftime("%H:%M:%S", time.localtime(packet.ts))
            label.set_markup(
                f'<span foreground="#6e7681">#{packet.number}</span> '
                f'<span foreground="#8b949e">{stamp}</span> '
                f'<span foreground="#79c0ff">{escape(packet.src)}:{escape(packet.sport)}</span> '
                f'<span foreground="#484f58">|</span> City: '
                f'<span foreground="#ff6b6b" weight="bold">{escape(packet.city_text)}</span> '
                f'<span foreground="#484f58">|</span> Country: '
                f'{escape(packet.country_text)} ({escape(packet.iso_text)})'
            )
        for label in row_labels[len(packets):]:
            label.set_markup("")

    def tick() -> bool:
        changed = False
        while True:
            try:
                packets.append(out_queue.get_nowait())
                changed = True
            except queue.Empty:
                break
        if changed:
            render()

        text, is_error = capture.status
        status.set_text(text)
        context = dot.get_style_context()
        if is_error:
            context.add_class("error")
        else:
            context.remove_class("error")
        count = getattr(capture, "count", 0)
        if getattr(capture, "unique", False):
            counter.set_text(f"{count} pkt - {len(capture.seen)} IP")
        else:
            counter.set_text(f"{count} pkt")
        return True

    def place_window() -> bool:
        display = Gdk.Display.get_default()
        try:
            monitor = display.get_monitor(args.monitor)
        except Exception:
            monitor = display.get_primary_monitor() or display.get_monitor(0)
        workarea = monitor.get_workarea()
        x = workarea.x + workarea.width - width - margin
        y = workarea.y + margin
        window.move(x, y)
        return False

    cleanup_done = False

    def cleanup() -> None:
        nonlocal cleanup_done
        if cleanup_done:
            return
        cleanup_done = True
        capture.stop()
        try:
            capture.join(timeout=3)
        except RuntimeError:
            pass

    def on_destroy(*_args) -> None:
        cleanup()
        Gtk.main_quit()

    window.connect("destroy", on_destroy)

    def on_signal(_signum, _frame) -> None:
        GLib.idle_add(window.close)

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, on_signal)
        except (ValueError, OSError):
            pass

    window.show_all()
    GLib.timeout_add(120, tick)
    GLib.timeout_add(60, place_window)
    GLib.timeout_add(500, place_window)

    try:
        Gtk.main()
    finally:
        cleanup()


# -------------------------------------------------------------------------- main
def _raise_keyboard_interrupt(_signum, _frame) -> None:
    raise KeyboardInterrupt


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Tampilkan kota/negara source IP publik dari paket UDP "
                    "di overlay kanan atas (atau console).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--console", action="store_true",
                        help="tampilkan di terminal, tanpa overlay GTK")
    parser.add_argument("--unique", action="store_true",
                        help="tampilkan tiap source IP hanya sekali")
    parser.add_argument("--interface", "-i", default="any",
                        help="interface capture (default: any)")
    parser.add_argument("--filter", default="udp",
                        help="BPF filter capture (default: udp)")
    parser.add_argument("--monitor", type=int, default=0,
                        help="index monitor untuk overlay (default: 0)")
    parser.add_argument("--margin", type=int, default=20,
                        help="jarak overlay dari tepi layar (default: 20)")
    parser.add_argument("--width", type=int, default=620,
                        help="lebar overlay (default: 620)")
    parser.add_argument("--height", type=int, default=390,
                        help="tinggi overlay (default: 390)")
    parser.add_argument("--rows", type=int, default=12,
                        help="jumlah baris paket yang ditampilkan (default: 12)")
    parser.add_argument("--demo", action="store_true",
                        help="pakai data contoh (untuk menguji overlay)")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.rows < 1:
        args.rows = 1

    out_queue: "queue.Queue[Packet]" = queue.Queue(maxsize=2000)
    if args.demo:
        capture = DemoCapture(out_queue)
    else:
        capture = Capture(out_queue, args.interface, args.filter, args.unique)

    capture.start()
    try:
        if args.console:
            for sig in (signal.SIGTERM, signal.SIGHUP):
                try:
                    signal.signal(sig, _raise_keyboard_interrupt)
                except (ValueError, OSError):
                    pass
            run_console(out_queue, capture)
        else:
            run_overlay(out_queue, capture, args)
    finally:
        capture.stop()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
