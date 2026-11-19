"""Synthetic-only NSO0 tests. No copyrighted game files needed."""
import contextlib
import io
import json
import struct
import tempfile
import unittest
from pathlib import Path

from nso_audit import audit_bytes, main


def fixture(*, compressed=False, hashed=False, text_moff=0):
    header = bytearray(0x100)
    header[:4] = b"NSO0"
    flags = int(compressed) | (int(hashed) << 3)
    struct.pack_into("<I", header, 0xC, flags)
    struct.pack_into("<III", header, 0x10, 0x100, text_moff, 16 if compressed else 4)
    struct.pack_into("<I", header, 0x60, 4)
    return bytes(header) + b"ABCD"


class NsoAuditTests(unittest.TestCase):
    def test_valid_uncompressed(self):
        result = audit_bytes(fixture()[:0x100], 0x104)
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["segments"][0]["compression_codec"], "none")
        self.assertFalse(result["hashes_verified"])

    def test_valid_compressed_metadata_not_decompressed(self):
        result = audit_bytes(fixture(compressed=True, hashed=True)[:0x100], 0x104)
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["segments"][0]["compression_codec"], "lz4")
        self.assertFalse(result["segments"][0]["hash_verified"])

    def test_short_header(self):
        self.assertEqual(audit_bytes(b"NSO0", 4)["status"], "fail")

    def test_magic_rejection(self):
        b = bytearray(fixture()); b[:4] = b"NRO0"
        self.assertEqual(audit_bytes(b[:0x100], len(b))["status"], "fail")

    def test_file_range_rejection(self):
        h = bytearray(fixture()); struct.pack_into("<I", h, 0x10, 0xFFFF)
        self.assertEqual(audit_bytes(h[:0x100], len(h))["status"], "fail")

    def test_uncompressed_size_mismatch(self):
        h = bytearray(fixture()); struct.pack_into("<I", h, 0x18, 8)
        self.assertEqual(audit_bytes(h[:0x100], len(h))["status"], "fail")

    def test_memory_overlap_rejection(self):
        h = bytearray(fixture()); struct.pack_into("<III", h, 0x20, 0x104, 2, 4)
        struct.pack_into("<I", h, 0x64, 4)
        h += b"EFGH"
        result = audit_bytes(h[:0x100], len(h))
        self.assertEqual(result["status"], "fail")
        self.assertIn("memory ranges overlap", " ".join(result["errors"]))

    def test_file_overlap_rejection(self):
        h = bytearray(fixture()); struct.pack_into("<III", h, 0x20, 0x102, 4, 4)
        struct.pack_into("<I", h, 0x64, 4)
        h += b"EFGH"
        result = audit_bytes(h[:0x100], len(h))
        self.assertEqual(result["status"], "fail")
        self.assertIn("file ranges overlap", " ".join(result["errors"]))

    def test_cli_does_not_modify_source(self):
        with tempfile.TemporaryDirectory() as td:
            source = Path(td) / "main.nso"
            report = Path(td) / "report.json"
            source.write_bytes(fixture())
            before = source.read_bytes()
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main([str(source), "--json", "--output", str(report)]), 0)
            self.assertEqual(source.read_bytes(), before)
            self.assertEqual(json.loads(report.read_text())["status"], "pass")
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main([str(source), "--output", str(report)]), 2)


if __name__ == "__main__":
    unittest.main()
