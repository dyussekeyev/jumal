import re
from typing import Optional

HASH_TYPES = {
    32: "md5",
    40: "sha1",
    64: "sha256"
}

HEX_RE = re.compile(r"^[0-9a-fA-F]+$")

def detect_hash_type(value: str) -> Optional[str]:
    if not isinstance(value, str):
        return None
    v = value.strip()
    if len(v) in HASH_TYPES and HEX_RE.fullmatch(v):
        return HASH_TYPES[len(v)]
    return None
