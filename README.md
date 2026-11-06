<div align="center">

# 🛰️ UDP Geo Sniffer

**Overlay kota & negara paket UDP di pojok kanan atas layar Linux/GNOME**
**+ ekstensi Wireshark untuk melihat dan memfilter City/Country.**

[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![GTK3](https://img.shields.io/badge/GTK-3-7FE719?logo=gtk&logoColor=black)](https://www.gtk.org/)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%2F%20GNOME-FCC624?logo=linux&logoColor=black)](#-kebutuhan)
[![Wireshark](https://img.shields.io/badge/Wireshark-4.x-1679A7?logo=wireshark&logoColor=white)](#-ekstensi-wireshark)
[![GeoIP](https://img.shields.io/badge/GeoIP-MaxMind%20GeoLite2-FF6B35)](#-database-geolite2-wajib)

</div>

---

## 📖 Tentang

**UDP Geo Sniffer** menangkap paket UDP dan menampilkan **source IP, port,
kota, dan negara** langsung di overlay kecil yang selalu berada di atas
jendela lain.

Tersedia **dua versi**:

- 🦈 **Versi tshark** — tanpa root, memakai capture engine Wireshark.
- 🔌 **Versi standalone** — tanpa tshark/Wireshark sama sekali, memakai
  raw socket Linux + `libmaxminddb`.

![Screenshot overlay](docs/screenshot.png)

Output contoh:

```text
#1 [UDP] 114.122.0.1:443  | City: Medan   | Country: Indonesia (ID)
#2 [UDP] 110.136.0.1:3478 | City: Jakarta | Country: Indonesia (ID)
```

> [!IMPORTANT]
> **Database GeoIP wajib ada.** File `GeoLite2-City.mmdb` **tidak
> disertakan** di repo ini karena lisensi MaxMind. Tanpa file tersebut,
> city/country tidak akan tampil.
> Unduh gratis di **<https://www.maxmind.com/en/geolite2/signup>** (perlu
> akun MaxMind), atau biarkan Wireshark mengunduhnya otomatis saat pertama
> kali dipakai.

---

## ✨ Fitur

- 🖥️ Overlay GTK3 selalu di atas, otomatis di pojok kanan atas layar.
- 🔴 Kota ditampilkan merah, negara beserta kode ISO.
- 🌍 Resolusi GeoIP dari database MaxMind GeoLite2.
- 🦈 **Versi tshark** — tanpa root, cukup ikut grup `wireshark`.
- 🔌 **Versi standalone** — tidak butuh tshark, dumpcap, atau Wireshark.
- 🧩 Ekstensi Lua Wireshark dengan field `udpgeo.*` siap dipakai sebagai
  kolom dan display filter.
- 📊 Profil Wireshark **UDP-Geo** dengan kolom City/Country.
- 🎛️ Mode `--console`, `--demo`, dan `--unique`.
- 🧵 Parsing Ethernet, VLAN, IPv4, IPv6, dan UDP (versi standalone).

---

## ⚖️ Perbandingan versi

| | 🦈 `geo_udp_sniffer.py` | 🔌 `geo_udp_sniffer_standalone.py` |
|---|:---:|:---:|
| Butuh tshark/Wireshark | ✅ Ya | ❌ Tidak |
| Butuh root / `CAP_NET_RAW` | ❌ Tidak | ✅ Ya |
| Database GeoIP | GeoLite2 milik Wireshark | `GeoLite2-City.mmdb` via `libmaxminddb` |
| Parsing paket | tshark | Ethernet, VLAN, IPv4, IPv6, UDP |
| Overlay GTK3 | ✅ | ✅ |
| Cocok untuk | Pemakaian harian tanpa root | Sistem tanpa Wireshark |

---

## 📦 Kebutuhan

### Arch / CachyOS

```bash
# 🦈 versi tshark + ekstensi Wireshark
sudo pacman -S --needed wireshark-cli python-gobject gtk3

# 🔌 versi standalone (Wireshark tidak perlu)
sudo pacman -S --needed python-gobject gtk3 libmaxminddb
```

### Debian / Ubuntu

```bash
# 🦈 versi tshark
sudo apt install tshark python3-gi gir1.2-gtk-3.0

# 🔌 versi standalone
sudo apt install python3-gi gir1.2-gtk-3.0 libmaxminddb0
```

Tambahkan user ke grup `wireshark` agar `dumpcap` bisa capture tanpa root:

```bash
sudo usermod -aG wireshark "$USER"
```

> [!NOTE]
> Logout/login (atau reboot) setelah menambahkan grup agar berlaku.

---

## 🚀 Cara pakai

### 🦈 Versi tshark (tanpa root)

```bash
./geo_udp_sniffer.py                 # overlay kanan atas
./geo_udp_sniffer.py --console       # tampil di terminal
./geo_udp_sniffer.py --demo          # data contoh
./geo_udp_sniffer.py --unique        # tiap source IP sekali
./geo_udp_sniffer.py -i enp7s0       # pilih interface
./geo_udp_sniffer.py --filter "udp"  # BPF filter
```

Opsi tampilan: `--monitor N`, `--margin N`, `--width N`, `--height N`,
`--rows N`.

### 🔌 Versi standalone (butuh root)

```bash
sudo -E ./geo_udp_sniffer_standalone.py            # overlay + capture
sudo -E ./geo_udp_sniffer_standalone.py --console  # tampil di terminal
./geo_udp_sniffer_standalone.py --demo             # tes overlay tanpa root
sudo -E ./geo_udp_sniffer_standalone.py --unique   # tiap IP sekali
sudo -E ./geo_udp_sniffer_standalone.py -i enp7s0
sudo -E ./geo_udp_sniffer_standalone.py --db /path/GeoLite2-City.mmdb
```

> [!TIP]
> `-E` pada `sudo` penting agar `DISPLAY` dan `XAUTHORITY` ikut terbawa ke
> proses root.

Alternatif tanpa menjalankan seluruh shell sebagai root — beri capability
pada binary Python:

```bash
sudo setcap cap_net_raw+ep "$(readlink -f "$(command -v python3)")"
```

Hentikan dengan tombol **x** di overlay atau `Ctrl+C` di terminal.

---

## 🦈 Ekstensi Wireshark

Pasang plugin, profil, dan launcher GNOME dengan satu perintah:

```bash
./install.sh
```

Atau manual:

```bash
mkdir -p ~/.local/lib/wireshark/plugins
cp wireshark/geo_udp.lua ~/.local/lib/wireshark/plugins/

mkdir -p ~/.config/wireshark/profiles/UDP-Geo
cp wireshark/UDP-Geo/preferences ~/.config/wireshark/profiles/UDP-Geo/
```

Lalu di Wireshark:

1. **Analyze → Reload Lua Plugins** (atau restart Wireshark).
2. Pilih profil **UDP-Geo** di menu profil kanan bawah.

### 🏷️ Field yang tersedia

| Field | Keterangan |
|---|---|
| `udpgeo.src_city` | Kota source |
| `udpgeo.src_country` | Negara source |
| `udpgeo.src_country_iso` | Kode ISO negara source |
| `udpgeo.dst_city` | Kota destination |
| `udpgeo.dst_country` | Negara destination |
| `udpgeo.dst_country_iso` | Kode ISO negara destination |
| `udpgeo.src_location` | Ringkasan lokasi source |
| `udpgeo.dst_location` | Ringkasan lokasi destination |

### 🔎 Contoh display filter

```text
udpgeo.src_city == "Jakarta"
udpgeo.src_country == "Indonesia"
udpgeo.src_location contains "Medan"
udpgeo.src_country_iso == "ID"
```

---

## 🌍 Database GeoLite2 (wajib)

Repo ini **tidak menyertakan** `GeoLite2-City.mmdb` karena lisensinya milik
MaxMind dan tidak boleh didistribusikan ulang di repo publik. Database ini
**wajib** agar city/country bisa ditampilkan.

Link download resmi MaxMind:

- 📝 Daftar akun gratis: **<https://www.maxmind.com/en/geolite2/signup>**
- ⬇️ Halaman download (setelah login):
  **<https://www.maxmind.com/en/accounts/current/geoip/downloads>**
- 📚 Info lisensi & data GeoLite2:
  **<https://dev.maxmind.com/geoip/geolite2-free-geolocation-data>**

Pilih **GeoLite2 City → Download GZIP (.tar.gz)**, lalu ekstrak dan salin:

```bash
tar -xzf GeoLite2-City_*.tar.gz
mkdir -p ~/.local/share/wireshark/maxmind
cp GeoLite2-City_*/GeoLite2-City.mmdb ~/.local/share/wireshark/maxmind/
```

Alternatif tanpa akun MaxMind: buka Wireshark sekali dan aktifkan
**Edit → Preferences → Name Resolution → Enable MaxMind geolocation**.
Wireshark akan mengunduh database ke
`~/.local/share/wireshark/maxmind/`.

Lokasi file yang dicari aplikasi:

- `~/.local/share/wireshark/maxmind/GeoLite2-City.mmdb`
- `~/.local/share/GeoIP/GeoLite2-City.mmdb`
- `/usr/share/GeoIP/GeoLite2-City.mmdb`
- `/usr/share/wireshark/maxmind/GeoLite2-City.mmdb`

Atau tentukan langsung dengan `--db /path/GeoLite2-City.mmdb` pada versi
standalone.

---

## 📝 Catatan

- 🪟 Window dipaksa lewat **XWayland** (`GDK_BACKEND=x11`) supaya bisa
  diposisikan di kanan atas dan selalu di atas. Di Wayland murni, compositor
  yang menentukan posisi window.
- 🛰️ Kota bisa tampil **Unknown City** untuk IP anycast seperti Google
  (`74.125.x.x`, `142.250.x.x`) atau Cloudflare. Negara tetap tampil.
- 🔒 Tanpa root, versi standalone menampilkan pesan:
  `Butuh izin root/CAP_NET_RAW`.
- 🖥️ Jika GTK menolak terbuka saat dijalankan sebagai root, pakai versi
  tshark atau jalankan versi standalone dengan `--console`.

---

## 📁 Struktur repo

```text
.
├── 🐍 geo_udp_sniffer.py              # versi tshark/dumpcap
├── 🔌 geo_udp_sniffer_standalone.py   # versi raw socket + libmaxminddb
├── ⚙️ install.sh                      # pasang plugin + profil + launcher
├── 🦈 wireshark/
│   ├── geo_udp.lua
│   └── UDP-Geo/preferences
├── 🖥️ desktop/                        # launcher GNOME
├── 🖼️ docs/screenshot.png
└── 📜 legacy/                         # versi Windows lama
```

---

## 📄 Lisensi

Belum ditentukan. Tambahkan file `LICENSE` sebelum dipublikasikan bila perlu.

---

<div align="center">

⭐ **Kalau repo ini berguna, jangan lupa kasih star!** ⭐

</div>
