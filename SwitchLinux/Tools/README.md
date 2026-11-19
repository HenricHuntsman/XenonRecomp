# SwitchLinux — NSO0 read-only inventory (stage 1)

This folder is an **independent add-on** for the experimental `SwitchLinux` host preflight developed in Codespaces. It does not replace the existing `switch-linux-doctor`, change XenonRecomp, decode encrypted Nintendo packages or execute a Switch game.

## Run

```bash
python3 -m unittest discover -s SwitchLinux/Tools -p 'test_*.py' -v
python3 SwitchLinux/Tools/nso_audit.py /path/to/your/already-extracted/main.nso --json
python3 SwitchLinux/Tools/nso_audit.py /path/to/main.nso --output /tmp/switchlinux-nso-report.json
```

The input must be an existing **unencrypted/extracted NSO0 file**, not XCI/NSP/NCA. The tool reads only the 0x100-byte header, checks segment file bounds, detects memory and file overlaps, identifies the advertised segment compression mode, and reports declared hashes as **unverified**. It cannot establish that a compressed segment decodes correctly, that code is valid ARM64, or that any Linux runtime or game runs. SHA-256 validation, LZ4/ZBIC decompression, segment relocation, dynamic symbols, Horizon services and Vulkan rendering remain future milestones.

Reference format: [Switchbrew NSO0](https://switchbrew.org/wiki/NSO0). Game images and keys are never placed in this repo.
