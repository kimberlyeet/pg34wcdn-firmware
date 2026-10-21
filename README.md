# PG34WCDN standby indicator patcher

An offline, source-only tool for compatible ASUS PG34WCDN / RTD2739 firmware
images. It makes the ordinary
standby LED honor the OSD Power Indicator preference, retaining the existing
standby policy when the preference is enabled.

**Firmware is not included.** Supply your own firmware binary; the patcher reads
it locally and generates a separate modified image. The tool performs no
flashing or hardware communication.

> **Validation status:** MCM102 is the only firmware version validated against an
> actual image. Static success does not establish that an image is safe to flash.
> No hardware validation was performed by this tool.

## Contents

- [Quick start](#quick-start)
- [Supported firmware](#supported-firmware)
- [Compatibility checks](#compatibility-checks)
- [What the patch changes](#what-the-patch-changes)
- [Static analysis and its limits](#static-analysis-and-its-limits)
- [Validation and tests](#validation-and-tests)
- [Source files](#source-files)

## Quick start

**Requirements:** Python 3.10 or newer and your own firmware binary.
There are no third-party dependencies. The patcher runs offline without an
assembler, monitor connection or vendor updater.

Run these commands from this repository's root (the directory containing
`patcher.py`).

### 1. Inspect the image

```sh
python3 patcher.py inspect firmware.bin
```

`inspect` writes no files. It reports compatibility, discovered addresses, image
size, hash and CRC.

### 2. Create a patched image

```sh
python3 patcher.py patch firmware.bin \
  firmware-indicator-fix.bin \
  --manifest patch-manifest.json
```

`patch` creates a separate image. The optional `--manifest` argument also writes
a JSON manifest containing:

- Input/output SHA-256 hashes.
- Exact changed ranges and their before/after bytes.
- CRC values, discovered locations and static-check results.

**Refusal behavior:** `already_patched` means this modification is recognized;
`patch` refuses to apply it twice. Errors return a nonzero exit code and an
explanation. There is no force option.

## Supported firmware

“Universal” means that filenames, firmware hashes, function locations and
compatible RAM offsets are discovered from the supplied image. It does not mean
every firmware version or monitor model is supported. The tool recognizes the
instruction structures established by the MCM102 investigation and refuses
unrecognized or ambiguous layouts.

A new version with a different implementation needs investigation and an updated
matcher, rather than a forced patch.

## Compatibility checks

Compatibility checks establish all of the following before patching:

1. **Image format and identity.** A flat image, in 64 KiB banks, between 64 KiB
   and 16 MiB, with PG34WCDN and RTD2739 identity markers and a valid CRC.
   Identity markers are format checks, not proof of authenticity.

2. **CRC implementation and coverage.** One recognized CRC-8 implementation,
   its full image-update receiver including partial final chunks, and the
   comparison of the calculated and received CRC. The receiver's embedded size
   must match the actual input length. CRC coverage includes the whole image
   with its final byte replaced by `FF`.

3. **Standby block and preference address.** One recognized action-7 standby
   block, its containing hook's stack frame and epilogue, and an independent
   normal/wake preference test targeting the same LED selector. These establish
   the preference RAM address without using the previous MCM102 file offsets.

4. **Policy and LED selector.** A recognized separate-policy implementation and
   a bounded analysis of the actual LED selector, covering 256 selector modes
   and four initial GPIO states.

5. **Control flow and scratch-value use.** Matching instruction boundaries and
   local branch targets, no other hook path entering the rewritten interior,
   no direct call or stored absolute pointer into that interior, and a check
   that the removed scratch value is overwritten before it is read at the
   continuation.

6. **Replacement behavior.** A 100-byte replacement that fits in place and
   passes 640 instruction-model cases covering every preference-byte value,
   both policy results and every combination of the suffix's relevant flag
   bits. These compare enabled-mode behavior, non-LED calls/writes, preserved
   registers and the desired GPIO output.

## What the patch changes

The patch preserves the image length and **modifies only the recognized standby
block and the final CRC byte**.

| Area | Behavior |
| --- | --- |
| Ordinary standby LED | Honors the OSD Power Indicator preference; retains the existing standby policy when enabled. |
| Policy call, cleanup calls and flag stores | Preserved, including flag store order. |
| Shared LED selector, panel data, EDIDs, calibration, boot code and pixel-cleaning routines | Unchanged. |
| Trampoline or padding storage | None used; the replacement fits in place. |
| Unexpected input instructions | Rejected. |

## Static analysis and its limits

The decoder uses the no-delay execution model established for this Realtek
code family. It is a bounded static model, not a complete CPU or monitor
emulator. Calls to cleanup and other helpers are summarized during the 640
block checks; those checks do not re-prove whole-firmware reachability,
interrupt behavior or subsequent maintenance/notification behavior for every
new image. The original investigation found an existing diagnostic-exit LED
override and maintenance blinking paths; this tool preserves those behaviors.

The tool does not remove signatures or guarantee that a vendor updater will
accept an image. **Static success does not establish that an image is safe to
flash.** The tool performs no flashing or hardware communication.

## Validation and tests

**MCM102 is the only firmware version validated against an actual image.** Its
patched output matches the reference modification byte for byte, including
the CRC, with **81 changed bytes** in total.

Relocated functions, a different input hash, changed compatible preference
addresses, larger images, malformed inputs and refusal behavior are covered by
synthetic tests. These tests use programs constructed in memory and require no
firmware files.

Run from this repository's root:

```sh
python3 -B -m unittest -v
```

## Source files

| File | Purpose |
| --- | --- |
| [`patcher.py`](patcher.py) | Discovery, validation, patch generation, manifest and CLI. |
| [`patterns.py`](patterns.py) | Authored semantic specifications of supported structures. |
| [`mips16.py`](mips16.py) | Instruction decoding, encoding and bounded execution. |
| [`test_patcher.py`](test_patcher.py) | Synthetic tests and a source-tree contents check. |