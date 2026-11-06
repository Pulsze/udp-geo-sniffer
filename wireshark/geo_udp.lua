-- geo_udp.lua
-- Ekstensi Wireshark: menampilkan City / Country (MaxMind GeoLite2) untuk
-- paket UDP, dengan field yang bisa difilter dan dipakai sebagai kolom.
--
-- Pasang di:
--   ~/.local/lib/wireshark/plugins/geo_udp.lua
--
-- Aktifkan geoip MaxMind di Wireshark:
--   Preferences -> Name Resolution -> "Enable MaxMind geolocation for IP
--   address and IP protocol" (default: aktif). Database dibaca dari
--   ~/.local/share/wireshark/maxmind/ (GeoLite2-City.mmdb).
--
-- Field yang dihasilkan:
--   udpgeo.src_city          udpgeo.dst_city
--   udpgeo.src_country       udpgeo.dst_country
--   udpgeo.src_country_iso   udpgeo.dst_country_iso
--   udpgeo.src_location      udpgeo.dst_location   (ringkasan siap-pakai)
--
-- Contoh display filter:
--   udpgeo.src_city == "Jakarta"
--   udpgeo.src_country == "Indonesia"
--   udpgeo.src_location contains "Medan"

local udpgeo = Proto("udpgeo", "UDP GeoIP")

local function string_field(abbr, name)
    return ProtoField.string(abbr, name)
end

local f_src_city = string_field("udpgeo.src_city", "Source City")
local f_src_country = string_field("udpgeo.src_country", "Source Country")
local f_src_iso = string_field("udpgeo.src_country_iso", "Source Country ISO")
local f_src_location = string_field("udpgeo.src_location", "Source Location")
local f_dst_city = string_field("udpgeo.dst_city", "Destination City")
local f_dst_country = string_field("udpgeo.dst_country", "Destination Country")
local f_dst_iso = string_field("udpgeo.dst_country_iso", "Destination Country ISO")
local f_dst_location = string_field("udpgeo.dst_location", "Destination Location")

udpgeo.fields = {
    f_src_city, f_src_country, f_src_iso, f_src_location,
    f_dst_city, f_dst_country, f_dst_iso, f_dst_location,
}

-- Field bawaan Wireshark (diisi dari database MaxMind).
local ef_udp_sport = Field.new("udp.srcport")

local ef_src_city4 = Field.new("ip.geoip.src_city")
local ef_src_city6 = Field.new("ipv6.geoip.src_city")
local ef_src_country4 = Field.new("ip.geoip.src_country")
local ef_src_country6 = Field.new("ipv6.geoip.src_country")
local ef_src_iso4 = Field.new("ip.geoip.src_country_iso")
local ef_src_iso6 = Field.new("ipv6.geoip.src_country_iso")

local ef_dst_city4 = Field.new("ip.geoip.dst_city")
local ef_dst_city6 = Field.new("ipv6.geoip.dst_city")
local ef_dst_country4 = Field.new("ip.geoip.dst_country")
local ef_dst_country6 = Field.new("ipv6.geoip.dst_country")
local ef_dst_iso4 = Field.new("ip.geoip.dst_country_iso")
local ef_dst_iso6 = Field.new("ipv6.geoip.dst_country_iso")

local function value(field)
    if not field then
        return nil
    end
    local v = field()
    if v == nil then
        return nil
    end
    if type(v) == "table" then
        v = v[1]
    end
    if v == nil then
        return nil
    end
    local s = tostring(v)
    if s == "" or s == "<unknown>" then
        return nil
    end
    return s
end

local function first(a, b)
    return value(a) or value(b)
end

local function location(city, country, iso)
    local parts = {}
    if city then
        table.insert(parts, city)
    end
    if country then
        if iso then
            table.insert(parts, string.format("%s (%s)", country, iso))
        else
            table.insert(parts, country)
        end
    elseif iso then
        table.insert(parts, iso)
    end
    if #parts == 0 then
        return nil
    end
    return table.concat(parts, ", ")
end

function udpgeo.dissector(buffer, pinfo, tree)
    -- Hanya untuk paket UDP.
    if value(ef_udp_sport) == nil then
        return 0
    end

    local src_city = first(ef_src_city4, ef_src_city6)
    local src_country = first(ef_src_country4, ef_src_country6)
    local src_iso = first(ef_src_iso4, ef_src_iso6)
    local dst_city = first(ef_dst_city4, ef_dst_city6)
    local dst_country = first(ef_dst_country4, ef_dst_country6)
    local dst_iso = first(ef_dst_iso4, ef_dst_iso6)

    if not (src_city or src_country or src_iso or dst_city or dst_country or dst_iso) then
        return 0
    end

    local src_location = location(src_city, src_country, src_iso)
    local dst_location = location(dst_city, dst_country, dst_iso)

    local label = "UDP GeoIP"
    if src_location then
        label = label .. " - " .. src_location
    end
    local subtree = tree:add(udpgeo, buffer(), label)

    if src_city then subtree:add(f_src_city, src_city) end
    if src_country then subtree:add(f_src_country, src_country) end
    if src_iso then subtree:add(f_src_iso, src_iso) end
    if src_location then subtree:add(f_src_location, src_location) end

    if dst_city then subtree:add(f_dst_city, dst_city) end
    if dst_country then subtree:add(f_dst_country, dst_country) end
    if dst_iso then subtree:add(f_dst_iso, dst_iso) end
    if dst_location then subtree:add(f_dst_location, dst_location) end

    return 0
end

register_postdissector(udpgeo)
