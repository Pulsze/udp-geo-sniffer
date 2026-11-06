"""
UDP Geo Sniffer (City + Country)

Pemakaian (Windows):
  python udp_geo_sniffer.py               -> tampil di CMD (otomatis minta Administrator)
  python udp_geo_sniffer.py --background  -> jalan tersembunyi di belakang layar, hasil ke file log
  python udp_geo_sniffer.py --stop        -> hentikan mode background
  python udp_geo_sniffer.py --watch       -> pantau log mode background secara real-time (live)
  tambahkan --unique                      -> tampilkan tiap IP hanya sekali (default: SEMUA paket)
"""
import ctypes
import ipaddress
import logging
import os
import sys
import time
import traceback
from functools import lru_cache
from logging.handlers import RotatingFileHandler

SCRIPT = os.path.abspath(__file__)
BASE_DIR = os.path.dirname(SCRIPT)
CITY_DB_PATH = os.path.join(BASE_DIR, "GeoLite2-City.mmdb")
LOG_FILE = os.path.join(BASE_DIR, "geo_sniffer.log")
STOP_FILE = os.path.join(BASE_DIR, "geo_sniffer.stop")

log = logging.getLogger("geo")
reader = None
seen_ips = set()
UNIQUE_ONLY = "--unique" in sys.argv
packet_count = 0

# Kode warna ANSI untuk CMD
COLOR_RED = "\033[91m"
COLOR_RESET = "\033[0m"


# ---------------------------------------------------------------- helper Windows
def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def setup_console():
    """Mencegah CMD membeku (QuickEdit) dan mengaktifkan dukungan warna ANSI di CMD Windows."""
    try:
        k32 = ctypes.windll.kernel32
        
        # Nonaktifkan QuickEdit Mode pada STDIN (-10)
        h_in = k32.GetStdHandle(-10)
        mode_in = ctypes.c_uint32()
        if k32.GetConsoleMode(h_in, ctypes.byref(mode_in)):
            new_mode_in = (mode_in.value & ~0x0040) | 0x0080
            k32.SetConsoleMode(h_in, new_mode_in)
            
        # Aktifkan Virtual Terminal Processing pada STDOUT (-11) untuk mendukung warna ANSI
        h_out = k32.GetStdHandle(-11)
        mode_out = ctypes.c_uint32()
        if k32.GetConsoleMode(h_out, ctypes.byref(mode_out)):
            k32.SetConsoleMode(h_out, mode_out.value | 0x0004)
    except Exception:
        pass


def relaunch_as_admin(extra_args, visible):
    exe = sys.executable
    if not visible:
        pyw = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
        if os.path.exists(pyw):
            exe = pyw
    params = " ".join(f'"{a}"' for a in [SCRIPT] + extra_args)
    ret = ctypes.windll.shell32.ShellExecuteW(
        None, "runas", exe, params, BASE_DIR, 1 if visible else 0
    )
    return ret > 32


# ---------------------------------------------------------------- logika GeoIP
@lru_cache(maxsize=4096)
def lookup(ip: str):
    import geoip2.errors

    try:
        res = reader.city(ip)
    except (geoip2.errors.AddressNotFoundError, ValueError):
        return None
    return (
        res.city.name or "Unknown City",
        res.country.name or "Unknown Country",
        res.country.iso_code or "??",
    )


def is_public(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def packet_callback(packet):
    global packet_count
    try:
        from scapy.all import IP, UDP

        if IP not in packet or UDP not in packet:
            return
            
        # Ambil IP pengirim (Source IP)
        src_ip = packet[IP].src
        
        # Filter: Hanya IP pengirim publik (mengabaikan IP dari perangkat ini / lokal)
        if not is_public(src_ip):
            return
            
        if UNIQUE_ONLY:
            if src_ip in seen_ips:
                return
            seen_ips.add(src_ip)

        result = lookup(src_ip)
        if result is None:
            return
            
        city, country, iso = result
        packet_count += 1
        
        # Log hasil dengan nama kota berwarna merah di CMD
        log.info(
            "#%d [UDP] %-15s:%-5s | City: %s%s%s | Country: %s (%s)",
            packet_count, src_ip, packet[UDP].sport, COLOR_RED, city, COLOR_RESET, country, iso,
        )
    except Exception:
        log.exception("Gagal memproses paket")


def run_sniffer():
    from scapy.all import AsyncSniffer

    def start():
        s = AsyncSniffer(filter="udp", prn=packet_callback, store=0)
        s.start()
        time.sleep(2)
        return s

    sniffer = start()
    try:
        while not os.path.exists(STOP_FILE):
            time.sleep(1)
            if not sniffer.running:
                log.warning("Sniffer berhenti tiba-tiba, mencoba start ulang...")
                time.sleep(3)
                try:
                    sniffer = start()
                except Exception:
                    log.exception("Restart sniffer gagal")
    finally:
        try:
            sniffer.stop()
        except Exception:
            pass


def setup_logging(to_console):
    log.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s %(message)s", "%H:%M:%S")
    fh = RotatingFileHandler(LOG_FILE, maxBytes=2_000_000, backupCount=3, encoding="utf-8")
    fh.setFormatter(fmt)
    log.addHandler(fh)
    if to_console and sys.stdout is not None:
        ch = logging.StreamHandler(sys.stdout)
        ch.setFormatter(fmt)
        ch.terminator = "\n"
        log.addHandler(ch)


def init_reader():
    global reader
    import geoip2.database

    if not os.path.exists(CITY_DB_PATH):
        log.error("Database tidak ditemukan: %s", CITY_DB_PATH)
        return False
    reader = geoip2.database.Reader(CITY_DB_PATH)
    return True


# ---------------------------------------------------------------- entry point
def main():
    args = sys.argv[1:]

    if "--stop" in args:
        open(STOP_FILE, "w").close()
        print("Sinyal stop dikirim. Mode background akan berhenti dalam beberapa detik.")
        return

    if "--watch" in args:
        print(f"Memantau {LOG_FILE} secara real-time (Ctrl+C untuk keluar)\n")
        try:
            while not os.path.exists(LOG_FILE):
                time.sleep(1)
            with open(LOG_FILE, "r", encoding="utf-8", errors="replace") as f:
                f.seek(0, os.SEEK_END)
                while True:
                    line = f.readline()
                    if line:
                        print(line, end="", flush=True)
                    else:
                        time.sleep(0.2)
        except KeyboardInterrupt:
            pass
        return

    if "--background" in args:
        if os.path.exists(STOP_FILE):
            os.remove(STOP_FILE)
        if relaunch_as_admin(["--worker"] + [a for a in args if a == "--unique"], visible=False):
            print("Berjalan di belakang layar (tanpa jendela).")
            print(f"Hasil tersimpan di : {LOG_FILE}")
            print("Hentikan dengan    : python udp_geo_sniffer.py --stop")
        else:
            print("Gagal start: izin Administrator ditolak.")
        return

    worker = "--worker" in args
    if not is_admin():
        if not worker and relaunch_as_admin([a for a in args if a == "--unique"], visible=True):
            return
        print("Perlu hak Administrator.")
        return

    if os.path.exists(STOP_FILE):
        os.remove(STOP_FILE)
    setup_logging(to_console=not worker)
    if not worker:
        setup_console()
        print("=" * 70)
        print("  UDP GeoLite Sniffer (City + Country) - Real-Time")
        print("=" * 70)
        print("Membaca SEMUA paket UDP secara real-time. Ctrl+C untuk berhenti.\n")

    try:
        if not init_reader():
            return
        log.info("Sniffer dimulai. Log: %s", LOG_FILE)
        run_sniffer()
    except KeyboardInterrupt:
        log.info("Dihentikan oleh pengguna.")
    except Exception:
        log.error("ERROR FATAL:\n%s", traceback.format_exc())
    finally:
        if reader:
            reader.close()
        log.info("Sniffer berhenti.")
        if not worker:
            input("\nTekan Enter untuk menutup...")


if __name__ == "__main__":
    main()