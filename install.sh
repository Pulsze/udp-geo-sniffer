#!/usr/bin/env bash
# Pasang ekstensi Wireshark, profil UDP-Geo, dan launcher GNOME.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLUGIN_DIR="${HOME}/.local/lib/wireshark/plugins"
PROFILE_DIR="${HOME}/.config/wireshark/profiles/UDP-Geo"
APP_DIR="${HOME}/.local/share/applications"

mkdir -p "$PLUGIN_DIR" "$PROFILE_DIR" "$APP_DIR"

install -m 644 "$ROOT/wireshark/geo_udp.lua" "$PLUGIN_DIR/geo_udp.lua"
install -m 644 "$ROOT/wireshark/UDP-Geo/preferences" "$PROFILE_DIR/preferences"

cat > "$APP_DIR/geo-udp-sniffer.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=UDP Geo Sniffer
Comment=Overlay kota dan negara paket UDP (GeoLite2)
Exec=python3 "$ROOT/geo_udp_sniffer.py"
Icon=network-wireless
Terminal=false
Categories=Network;Monitor;
StartupNotify=false
EOF

echo "Terpasang:"
echo "  plugin  : $PLUGIN_DIR/geo_udp.lua"
echo "  profil  : $PROFILE_DIR/preferences"
echo "  launcher: $APP_DIR/geo-udp-sniffer.desktop"
echo
echo "Di Wireshark: Analyze -> Reload Lua Plugins, lalu pilih profil UDP-Geo."
