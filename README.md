**PG34WCDN standby indicator patcher** is an offline, source-only tool for
compatible ASUS PG34WCDN / RTD2739 firmware images. It makes the ordinary
standby LED honor the OSD Power Indicator preference, retaining the existing
standby policy when the preference is enabled.

“Universal” means that filenames, firmware hashes, function locations and
compatible RAM offsets are discovered from the supplied image. It does not mean
every firmware version or monitor model is supported. The tool recognizes the
instruction structures established by the MCM102 investigation and refuses
unrecognized or ambiguous layouts. A new version with a different implementation
needs investigation and an updated matcher, rather than a forced patch.

Firmware is not included. Supply your own firmware binary; the patcher reads
it locally and generates a separate modified image. Tests use synthetic
programs constructed in memory and require no firmware files.

Python 3.10 or newer is required. There are no third-party dependencies, and
the patcher runs offline without an assembler, monitor connection or vendor
updater. Run these commands from the repository root:

```sh
python3 patcher.py inspect firmware.bin

python3 patcher.py patch firmware.bin \
  firmware-indicator-fix.bin \
  --manifest patch-manifest.json
```

`inspect` writes no files. It reports compatibility, discovered addresses, image
size, hash and CRC. `already_patched` means this modification is recognized;
`patch` refuses to apply it twice. Errors return a nonzero exit code and an
explanation. There is no force option.

`patch` creates a separate image and, optionally, a JSON manifest containing
input/output SHA-256 hashes, exact changed ranges and their before/after bytes,
CRC values, discovered locations and static-check results.

Compatibility checks establish all of the following before patching:

- A flat image, in 64 KiB banks, between 64 KiB and 16 MiB, with PG34WCDN and
  RTD2739 identity markers and a valid CRC. Identity markers are format checks,
  not proof of authenticity.
- One recognized CRC-8 implementation, its full image-update receiver including
  partial final chunks, and the comparison of the calculated and received CRC.
  The receiver's embedded size must match the actual input length. CRC coverage
  includes the whole image with its final byte replaced by `FF`.
- One recognized action-7 standby block, its containing hook's stack frame and
  epilogue, and an independent normal/wake preference test targeting the same
  LED selector. These establish the preference RAM address without using the
  previous MCM102 file offsets.
- A recognized separate-policy implementation and a bounded analysis of the
  actual LED selector, covering 256 selector modes and four initial GPIO states.
- Matching instruction boundaries and local branch targets, no other hook path
  entering the rewritten interior, no direct call or stored absolute pointer
  into that interior, and a check that the removed scratch value is overwritten
  before it is read at the continuation.
- A 100-byte replacement that fits in place and passes 640 instruction-model
  cases covering every preference-byte value, both policy results and every
  combination of the suffix's relevant flag bits. These compare enabled-mode
  behavior, non-LED calls/writes, preserved registers and the desired GPIO output.

The patch preserves the image length and modifies only the recognized standby
block and the final CRC byte. It keeps the policy call, cleanup calls and flag
store order. It does not change the shared LED selector, panel data, EDIDs,
calibration, boot code or pixel-cleaning routines. No trampoline or padding
storage is used. Unexpected input instructions cause rejection.

The decoder uses the no-delay execution model established for this Realtek
code family. It is a bounded static model, not a complete CPU or monitor
emulator. Calls to cleanup and other helpers are summarized during the 640
block checks; those checks do not re-prove whole-firmware reachability,
interrupt behavior or subsequent maintenance/notification behavior for every
new image. The original investigation found an existing diagnostic-exit LED
override and maintenance blinking paths; this tool preserves those behaviors.
It does not remove signatures or guarantee that a vendor updater will accept
an image. Static success does not establish that an image is safe to flash.
The tool performs no flashing or hardware communication.

MCM102 is the only firmware version validated against an actual image. Its
patched output matches the reference modification byte for byte, including
the CRC, with 81 changed bytes in total.
Relocated functions, a different input hash, changed compatible preference
addresses, larger images, malformed inputs and refusal behavior are covered by
synthetic tests:

```sh
python3 -B -m unittest -v
```

The source tree consists of:

- `patcher.py`: discovery, validation, patch generation, manifest and CLI.
- `patterns.py`: authored semantic specifications of supported structures.
- `mips16.py`: instruction decoding, encoding and bounded execution.
- `test_patcher.py`: synthetic tests and a source-tree contents check.

For any separately reviewed hardware validation, compare stock and modified
behavior with the preference off/on during signal-loss standby, delayed standby,
wake and button-off/on. Complete manual and automatic pixel-cleaning cycles
with both preferences and compare their notifications and final states. The
existing diagnostic and maintenance exceptions must be distinguished from
ordinary standby. No such hardware validation was performed by this tool.
