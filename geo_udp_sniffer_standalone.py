#!/usr/bin/env python3
"""UDP Geo Sniffer Standalone - overlay kanan atas (Linux / GNOME).

Versi mandiri: TIDAK memakai tshark, dumpcap, atau Wireshark.
- Capture UDP langsung dengan raw socket Linux (AF_PACKET).
- GeoIP dibaca langsung dari GeoLite2-City.mmdb lewat libmaxminddb.

Karena memakai raw socket, jalankan dengan root:
  sudo -E ./geo_udp_sniffer_standalone.py

Pemakaian:
  ./geo_udp_sniffer_standalone.py --demo          -> data contoh (tanpa root)
  sudo -E ./geo_udp_sniffer_standalone.py         -> overlay + capture
  sudo -E ./geo_udp_sniffer_standalone.py --console
  ./geo_udp_sniffer_standalone.py --unique        -> tiap source IP sekali
  ./geo_udp_sniffer_standalone.py -i enp7s0 --db /path/GeoLite2-City.mmdb

Opsi lain:
  --monitor N   monitor yang dipakai (default 0)
  --margin N    jarak dari tepi layar (default 20 px)
  --width N     lebar overlay (default 620 px)
  --height N    tinggi overlay (default 390 px)

Ctrl+C di terminal (atau tombol x di overlay) untuk berhenti.
"""

from __future__ import annotations

import argparse
import ctypes
import ctypes.util
import functools
import ipaddress
import os
import queue
import signal
import socket
import struct
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass
from xml.sax.saxutils import escape

APP_NAME = "UDP Geo Sniffer (Standalone)"

# Paksa XWayland supaya window bisa diposisikan di kanan atas dan selalu
# di atas. Di Wayland murni, compositor yang menentukan posisi window.
os.environ.setdefault("GDK_BACKEND", "x11")

CITY_DB_CANDIDATES = (
    os.path.expanduser("~/.local/share/wireshark/maxmind/GeoLite2-City.mmdb"),
    os.path.expanduser("~/.local/share/GeoIP/GeoLite2-City.mmdb"),
    "/usr/share/GeoIP/GeoLite2-City.mmdb",
    "/var/lib/GeoIP/GeoLite2-City.mmdb",
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


# ------------------------------------------------------------------ GeoIP MMDB
# Pembaca GeoLite2 langsung lewat libmaxminddb (tanpa modul geoip2/tshark).
# Struct C di bawah mengikuti /usr/include/maxminddb.h.

class _MMDBLanguages(ctypes.Structure):
    _fields_ = [("count", ctypes.c_size_t),
                ("names", ctypes.POINTER(ctypes.c_char_p))]


class _MMDBDescriptions(ctypes.Structure):
    _fields_ = [("count", ctypes.c_size_t), ("descriptions", ctypes.c_void_p)]


class _MMDBMetadata(ctypes.Structure):
    _fields_ = [
        ("node_count", ctypes.c_uint32),
        ("record_size", ctypes.c_uint16),
        ("ip_version", ctypes.c_uint16),
        ("database_type", ctypes.c_char_p),
        ("languages", _MMDBLanguages),
        ("binary_format_major_version", ctypes.c_uint16),
        ("binary_format_minor_version", ctypes.c_uint16),
        ("build_epoch", ctypes.c_uint64),
        ("description", _MMDBDescriptions),
    ]


class _MMDBIPv4Start(ctypes.Structure):
    _fields_ = [("netmask", ctypes.c_uint16), ("node_value", ctypes.c_uint32)]


class _MMDBS(ctypes.Structure):
    _fields_ = [
        ("flags", ctypes.c_uint32),
        ("filename", ctypes.c_char_p),
        ("file_size", ctypes.c_ssize_t),
        ("file_content", ctypes.c_void_p),
        ("data_section", ctypes.c_void_p),
        ("data_section_size", ctypes.c_uint32),
        ("metadata_section", ctypes.c_void_p),
        ("metadata_section_size", ctypes.c_uint32),
        ("full_record_byte_size", ctypes.c_uint16),
        ("depth", ctypes.c_uint16),
        ("ipv4_start_node", _MMDBIPv4Start),
        ("metadata", _MMDBMetadata),
    ]


class _MMDBEntry(ctypes.Structure):
    _fields_ = [("mmdb", ctypes.c_void_p), ("offset", ctypes.c_uint32)]


class _MMDBLookupResult(ctypes.Structure):
    _fields_ = [("found_entry", ctypes.c_bool),
                ("entry", _MMDBEntry),
                ("netmask", ctypes.c_uint16)]


class _MMDBEntryDataUnion(ctypes.Union):
    _fields_ = [
        ("pointer", ctypes.c_uint32),
        ("utf8_string", ctypes.c_char_p),
        ("double_value", ctypes.c_double),
        ("bytes", ctypes.c_void_p),
        ("uint16", ctypes.c_uint16),
        ("uint32", ctypes.c_uint32),
        ("int32", ctypes.c_int32),
        ("uint64", ctypes.c_uint64),
        ("uint128", ctypes.c_ubyte * 16),
        ("boolean", ctypes.c_bool),
        ("float_value", ctypes.c_float),
        ("_align", ctypes.c_longdouble),
    ]


class _MMDBEntryData(ctypes.Structure):
    _fields_ = [
        ("has_data", ctypes.c_bool),
        ("data", _MMDBEntryDataUnion),
        ("offset", ctypes.c_uint32),
        ("offset_to_next", ctypes.c_uint32),
        ("data_size", ctypes.c_uint32),
        ("type", ctypes.c_uint32),
    ]


_libmaxmind = None


def _load_maxmind():
    global _libmaxmind
    if _libmaxmind is not None:
        return _libmaxmind
    name = ctypes.util.find_library("maxminddb")
    if not name:
        return None
    lib = ctypes.CDLL(name)
    lib.MMDB_open.argtypes = [ctypes.c_char_p, ctypes.c_uint32,
                              ctypes.POINTER(_MMDBS)]
    lib.MMDB_open.restype = ctypes.c_int
    lib.MMDB_close.argtypes = [ctypes.POINTER(_MMDBS)]
    lib.MMDB_lookup_string.argtypes = [
        ctypes.POINTER(_MMDBS), ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_int),
    ]
    lib.MMDB_lookup_string.restype = _MMDBLookupResult
    lib.MMDB_get_value.restype = ctypes.c_int
    lib.MMDB_strerror.argtypes = [ctypes.c_int]
    lib.MMDB_strerror.restype = ctypes.c_char_p
    _libmaxmind = lib
    return lib


class GeoDB:
    """Lookup kota/negara dari file GeoLite2-City.mmdb."""

    def __init__(self, path: str | None):
        self.path = path
        self.lib = _load_maxmind()
        self.db = _MMDBS()
        self.available = False
        self.error: str | None = None
        self._cache: dict[str, tuple[str, str, str]] = {}
        if self.lib is None:
            self.error = "libmaxminddb tidak ditemukan"
            return
        if not path or not os.path.isfile(path):
            self.error = "GeoLite2-City.mmdb tidak ditemukan"
            return
        rc = self.lib.MMDB_open(os.fsencode(path), 1, ctypes.byref(self.db))
        if rc != 0:
            msg = self.lib.MMDB_strerror(rc)
            self.error = msg.decode("utf-8", "replace") if msg else f"error {rc}"
            return
        self.available = True

    def _get(self, entry, *keys: str) -> str | None:
        data = _MMDBEntryData()
        args = [ctypes.byref(entry), ctypes.byref(data)]
        args.extend(ctypes.c_char_p(k.encode("ascii")) for k in keys)
        args.append(None)
        rc = self.lib.MMDB_get_value(*args)
        if rc != 0 or not data.has_data or data.type != 2:  # 2 = UTF-8 string
            return None
        return ctypes.string_at(data.data.utf8_string,
                                data.data_size).decode("utf-8", "replace")

    def lookup(self, ip: str) -> tuple[str, str, str]:
        if not self.available:
            return "", "", ""
        cached = self._cache.get(ip)
        if cached is not None:
            return cached

        gai_error = ctypes.c_int()
        db_error = ctypes.c_int()
        res = self.lib.MMDB_lookup_string(
            ctypes.byref(self.db), ip.encode("ascii"),
            ctypes.byref(gai_error), ctypes.byref(db_error),
        )
        if not res.found_entry:
            result = ("", "", "")
        else:
            city = self._get(res.entry, "city", "names", "en") or ""
            country = (self._get(res.entry, "country", "names", "en")
                       or self._get(res.entry, "registered_country", "names", "en")
                       or "")
            iso = (self._get(res.entry, "country", "iso_code")
                   or self._get(res.entry, "registered_country", "iso_code")
                   or "")
            result = (city, country, iso)

        if len(self._cache) > 8192:
            self._cache.clear()
        self._cache[ip] = result
        return result

    def close(self) -> None:
        if self.available:
            self.lib.MMDB_close(ctypes.byref(self.db))
            self.available = False


# ------------------------------------------------------------------ packet parser
def parse_udp_frame(frame: bytes) -> tuple[str, str] | None:
    """Ambil (source_ip, source_port) dari frame Ethernet + IPv4/IPv6 + UDP."""
    if len(frame) < 14:
        return None

    ethertype = struct.unpack_from("!H", frame, 12)[0]
    offset = 14
    # Lewati tag VLAN (802.1Q / QinQ).
    while ethertype in (0x8100, 0x88A8, 0x9100):
        if len(frame) < offset + 4:
            return None
        ethertype = struct.unpack_from("!H", frame, offset + 2)[0]
        offset += 4

    if ethertype == 0x0800:  # IPv4
        if len(frame) < offset + 20:
            return None
        version_ihl = frame[offset]
        if version_ihl >> 4 != 4:
            return None
        ihl = (version_ihl & 0x0F) * 4
        if ihl < 20 or len(frame) < offset + ihl + 8:
            return None
        if frame[offset + 9] != 17:  # UDP
            return None
        src = socket.inet_ntop(
            socket.AF_INET, frame[offset + 12:offset + 16])
        sport = struct.unpack_from("!H", frame, offset + ihl)[0]
        return src, str(sport)

    if ethertype == 0x86DD:  # IPv6
        if len(frame) < offset + 40:
            return None
        if frame[offset] >> 4 != 6:
            return None
        next_header = frame[offset + 6]
        pos = offset + 40
        # Lewati extension header yang umum sebelum UDP.
        while next_header in (0, 43, 44, 51, 60):
            if next_header == 44:  # fragment header
                if len(frame) < pos + 8:
                    return None
                next_header = frame[pos]
                pos += 8
            elif next_header == 51:  # authentication header
                if len(frame) < pos + 2:
                    return None
                header_len = (frame[pos + 1] + 2) * 4
                if len(frame) < pos + header_len:
                    return None
                next_header = frame[pos]
                pos += header_len
            else:
                if len(frame) < pos + 2:
                    return None
                header_len = (frame[pos + 1] + 1) * 8
                if len(frame) < pos + header_len:
                    return None
                next_header = frame[pos]
                pos += header_len
        if next_header != 17 or len(frame) < pos + 8:
            return None
        src = socket.inet_ntop(
            socket.AF_INET6, frame[offset + 8:offset + 24])
        sport = struct.unpack_from("!H", frame, pos)[0]
        return src, str(sport)

    return None


# --------------------------------------------------------------- raw capture
class RawCapture(threading.Thread):
    """Capture UDP langsung dengan AF_PACKET; butuh root/CAP_NET_RAW."""

    def __init__(self, out_queue: "queue.Queue[Packet]", interface: str,
                 unique: bool, db_path: str | None):
        super().__init__(daemon=True, name="raw-capture")
        self.out_queue = out_queue
        self.interface = interface
        self.unique = unique
        self.count = 0
        self.seen: set[str] = set()
        self.stop_event = threading.Event()
        self.sock: socket.socket | None = None
        self.geo = GeoDB(db_path)
        self._lock = threading.Lock()
        self._status = "Menyiapkan raw socket..."
        self._error = False

    @property
    def status(self) -> tuple[str, bool]:
        with self._lock:
            return self._status, self._error

    def set_status(self, text: str, error: bool = False) -> None:
        with self._lock:
            self._status = text
            self._error = error

    def run(self) -> None:
        try:
            sock = socket.socket(
                socket.AF_PACKET, socket.SOCK_RAW,
                socket.htons(0x0003),  # ETH_P_ALL
            )
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
            if self.interface and self.interface != "any":
                sock.bind((self.interface, 0))
            sock.settimeout(0.5)
            self.sock = sock
        except PermissionError:
            self.set_status(
                "Butuh izin root/CAP_NET_RAW. Jalankan: "
                "sudo -E ./geo_udp_sniffer_standalone.py", True)
            self.geo.close()
            return
        except OSError as exc:
            self.set_status(f"Gagal membuka raw socket: {exc}", True)
            self.geo.close()
            return

        note = ""
        if not self.geo.available:
            note = f" ({self.geo.error}; kota kosong)"
        self.set_status(
            f"Mendengarkan UDP publik di {self.interface}...{note}",
            not self.geo.available,
        )

        try:
            while not self.stop_event.is_set():
                try:
                    frame, addr = sock.recvfrom(65535)
                except socket.timeout:
                    continue
                except OSError as exc:
                    if self.stop_event.is_set():
                        break
                    self.set_status(f"Capture error: {exc}", True)
                    break

                # Lewati paket yang keluar dari host ini (hindari duplikat).
                if len(addr) >= 3 and addr[2] == 4:  # PACKET_OUTGOING
                    continue

                parsed = parse_udp_frame(frame)
                if parsed is None:
                    continue
                src, sport = parsed
                if not is_public(src):
                    continue
                if self.unique:
                    if src in self.seen:
                        continue
                    self.seen.add(src)

                city, country, iso = self.geo.lookup(src)
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
        finally:
            try:
                sock.close()
            except OSError:
                pass
            self.geo.close()
            if not self.stop_event.is_set():
                self.set_status("Capture berhenti.", True)
            else:
                self.set_status("Dihentikan.")

    def stop(self) -> None:
        self.stop_event.set()
        sock = self.sock
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


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
    parser.add_argument("--db", default=None,
                        help="path GeoLite2-City.mmdb (opsional)")
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
        db_path = args.db or find_city_db()
        capture = RawCapture(out_queue, args.interface, args.unique, db_path)

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
