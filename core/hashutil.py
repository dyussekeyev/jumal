import re

HASH_TYPES = {
    32: "md5",
    40: "sha1",
    64: "sha256"
}

HEX_RE = re.compile(r"^[0-9a-fA-F]+$")

def detect_hash_type(value: str):
    value = value.strip()
    if len(value) in HASH_TYPES and HEX_RE.match(value):
        return HASH_TYPES[len(value)]
    return None