#!/usr/bin/env python3
"""Read-only Switch NSO0 layout audit. Does NOT decompress, decrypt or execute code.

NSO0 header format: https://switchbrew.org/wiki/NSO0
"""
import argparse
import json
import struct
import sys
from pathlib import Path

HEADER_SIZE = 0x100
SEGMENTS = ("text", "rodata", "data")


def audit_bytes(header: bytes, file_size: int) -> dict:
    result = {
        "format": "NSO0", "audit_level": "header_and_bounds_only",
        "file_size": file_size, "status": "fail", "errors": [], "warnings": [],
        "segments": [], "decompressed": False, "hashes_verified": False,
        "instructions_executed": 0,
    }
    errors = result["errors"]
    if len(header) < HEADER_SIZE:
        errors.append(f"truncated header: {len(header)} bytes; need {HEADER_SIZE}")
        return result
    if header[:4] != b"NSO0":
        errors.append("not an NSO0 executable: magic mismatch")
        return result
    if file_size < HEADER_SIZE:
        errors.append("file shorter than NSO0 header")
        return result

    version, _reserved, flags = struct.unpack_from("<III", header, 4)
    result.update(version=version, flags=f"0x{flags:08x}",
                  module_id=header[0x40:0x60].hex(),
                  bss_size=struct.unpack_from("<I", header, 0x3C)[0])
    if flags & ~0xFF:
        result["warnings"].append(f"unrecognised flag bits: 0x{flags & ~0xFF:x}")
    if version != 0:
        result["warnings"].append(f"unusual NSO version {version}; layout may differ")
    if flags & 0x80:
        result["warnings"].append("ZBIC/zstd-based segment compression flagged; decoding not attempted")

    module_off = struct.unpack_from("<I", header, 0x1C)[0]
    module_size = struct.unpack_from("<I", header, 0x2C)[0]
    result["module_name"] = {"offset": module_off, "size": module_size}
    if module_size and (module_off < HEADER_SIZE or module_off + module_size > file_size):
        errors.append("module name range outside executable file")

    file_spans = []
    memory_spans = []
    for idx, name in enumerate(SEGMENTS):
        base = 0x10 + idx * 0x10
        foff, moff, decoded = struct.unpack_from("<III", header, base)
        stored = struct.unpack_from("<I", header, 0x60 + idx * 4)[0]
        compressed = bool(flags & (1 << idx))
        has_hash = bool(flags & (1 << (idx + 3)))
        codec = "zbic/zstd" if (compressed and flags & 0x80) else "lz4" if compressed else "none"
        seg = {
            "name": name, "file_offset": foff, "stored_size": stored,
            "memory_offset": moff, "decoded_size": decoded,
            "compressed": compressed, "compression_codec": codec,
            "hash_declared": has_hash, "hash_verified": False,
        }
        result["segments"].append(seg)
        if decoded == 0 and stored != 0:
            errors.append(f"{name}: stored bytes for empty memory segment")
        if decoded != 0 and stored == 0:
            errors.append(f"{name}: missing stored bytes for nonempty segment")
        if stored:
            if foff < HEADER_SIZE or foff + stored > file_size:
                errors.append(f"{name}: stored data outside executable file")
            else:
                file_spans.append((foff, foff + stored, name))
        if decoded:
            if moff + decoded > 0x1_0000_0000:
                errors.append(f"{name}: guest offset exceeds 32-bit module range")
            else:
                memory_spans.append((moff, moff + decoded, name))
            if not compressed and decoded != stored:
                errors.append(f"{name}: uncompressed segment has unequal stored/decoded sizes")
    for spans, label in ((file_spans, "file"), (memory_spans, "memory")):
        spans.sort()
        for prev, cur in zip(spans, spans[1:]):
            if cur[0] < prev[1]:
                errors.append(f"{label} ranges overlap: {prev[2]} and {cur[2]}")

    if any(s["hash_declared"] for s in result["segments"]):
        result["warnings"].append("declared SHA-256 segment hashes have NOT been checked")
    result["warnings"].append("NSO metadata only; no loading, CPU translation, decompression or gameplay")
    result["status"] = "pass" if not errors else "fail"
    return result


def audit_file(path: Path) -> dict:
    with path.open("rb") as f:
        header = f.read(HEADER_SIZE)
    return audit_bytes(header, path.stat().st_size)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("nso", type=Path, help="existing, locally extracted NSO0; not XCI/NSP")
    parser.add_argument("--json", action="store_true", help="machine-readable report to stdout")
    parser.add_argument("--output", type=Path, help="write a new JSON report, never overwrite")
    args = parser.parse_args(argv)
    try:
        result = audit_file(args.nso)
        result["input"] = str(args.nso)
        rendered = json.dumps(result, indent=2, sort_keys=True)
        if args.output:
            with args.output.open("x", encoding="utf-8") as output:
                output.write(rendered + "\n")
        if args.json:
            print(rendered)
        else:
            print(f"NSO audit: {result['status'].upper()} — {args.nso}")
            for seg in result["segments"]:
                print(f"  {seg['name']:<6}: stored={seg['stored_size']:,} decoded={seg['decoded_size']:,} "
                      f"codec={seg['compression_codec']} at file+0x{seg['file_offset']:x}")
            for err in result["errors"]:
                print("ERROR:", err)
            for warning in result["warnings"]:
                print("NOTE:", warning)
            if args.output:
                print("Report:", args.output)
        return 0 if result["status"] == "pass" else 1
    except (OSError, ValueError) as e:
        print(f"NSO audit: I/O error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
