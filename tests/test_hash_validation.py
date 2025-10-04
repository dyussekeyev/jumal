import pytest
from core.hashutil import detect_hash_type

def test_md5():
    assert detect_hash_type("a" * 32) == "md5"

def test_sha1():
    assert detect_hash_type("a" * 40) == "sha1"

def test_sha256():
    assert detect_hash_type("a" * 64) == "sha256"

def test_invalid_length():
    assert detect_hash_type("abc") is None

def test_non_hex():
    assert detect_hash_type("g" * 32) is None