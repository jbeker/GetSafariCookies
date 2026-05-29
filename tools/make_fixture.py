# /// script
# requires-python = ">=3.9"
# ///
"""Generate a deterministic Cookies.binarycookies fixture for tests."""
import struct
import sys

MAC_EPOCH_OFFSET = 978307200
HEADER_SIZE = 56  # bytes before the string blob in a cookie record

# (domain, name, path, value, expiry_unix, secure, http_only)
COOKIES = [
    ("example.com",        "sid",     "/",    "abc123",   1700000000, False, False),
    (".example.com",       "pref",    "/",    "dark",     1700000000, False, False),
    ("secure.example.com", "token",   "/app", "xyz",      1700000000, True,  False),
    ("auth.example.com",   "session", "/",    "deadbeef", 1700000000, True,  True),
]
# Split across two pages to exercise multi-page parsing.
PAGES = [COOKIES[:2], COOKIES[2:]]


def build_cookie(domain, name, path, value, expiry_unix, secure, http_only):
    flags = (0x1 if secure else 0) | (0x4 if http_only else 0)
    enc = lambda s: s.encode("utf-8") + b"\x00"
    d, n, p, v = enc(domain), enc(name), enc(path), enc(value)
    domain_off = HEADER_SIZE
    name_off = domain_off + len(d)
    path_off = name_off + len(n)
    value_off = path_off + len(p)
    total = value_off + len(v)
    out = bytearray(total)
    struct.pack_into("<i", out, 0, total)
    struct.pack_into("<i", out, 8, flags)
    struct.pack_into("<i", out, 16, domain_off)
    struct.pack_into("<i", out, 20, name_off)
    struct.pack_into("<i", out, 24, path_off)
    struct.pack_into("<i", out, 28, value_off)
    struct.pack_into("<d", out, 40, float(expiry_unix - MAC_EPOCH_OFFSET))
    struct.pack_into("<d", out, 48, 0.0)
    out[domain_off:domain_off + len(d)] = d
    out[name_off:name_off + len(n)] = n
    out[path_off:path_off + len(p)] = p
    out[value_off:value_off + len(v)] = v
    return bytes(out)


def build_page(cookies):
    records = [build_cookie(*c) for c in cookies]
    head = 4 + 4 + 4 * len(records) + 4  # tag + count + offsets + footer
    offsets, pos = [], head
    for r in records:
        offsets.append(pos)
        pos += len(r)
    page = bytearray()
    page += b"\x00\x00\x01\x00"            # page tag
    page += struct.pack("<i", len(records))
    for off in offsets:
        page += struct.pack("<i", off)     # offsets relative to page start
    page += b"\x00\x00\x00\x00"            # footer
    for r in records:
        page += r
    return bytes(page)


def build_file(pages):
    blobs = [build_page(p) for p in pages]
    out = bytearray()
    out += b"cook"
    out += struct.pack(">i", len(blobs))       # page count (big-endian)
    for b in blobs:
        out += struct.pack(">i", len(b))       # page sizes (big-endian)
    for b in blobs:
        out += b
    out += struct.pack(">i", 0)                # checksum (ignored by reader)
    out += b"\x07\x17\x20\x05\x00\x00\x00\x4b"  # footer (ignored by reader)
    return bytes(out)


if __name__ == "__main__":
    dest = sys.argv[1] if len(sys.argv) > 1 else "tests/fixtures/test.binarycookies"
    with open(dest, "wb") as f:
        f.write(build_file(PAGES))
    print(f"wrote {dest}")
