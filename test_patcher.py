"""Tests use authored synthetic programs built in memory, never vendor firmware."""
import sys
sys.dont_write_bytecode = True

from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest

from mips16 import BASE, CPU, Program, decode, encode
import patcher
import patterns


def put(image, pc, code):
    at = pc - BASE
    assert 0 <= at <= len(image)-len(code)
    image[at:at+len(code)] = code


def seal(image):
    image[-1] = patcher.image_crc(image)
    return bytes(image)


def synthetic_led(pc):
    # An independently authored dispatch, deliberately different from the vendor
    # leaf layout. Only its input/output contract is shared.
    p = Program(pc)
    for modes, label in [((0, 2, 4, 7), 'active'), ((3, 5), 'amber'), ((6, 13), 'off'), ((8,), 'partial')]:
        for mode in modes:
            p.emit('cmpi', 4, mode)
            p.emit('bteqz', label)
    p.emit('jr', 31)
    for label, outputs in [('active', (1, 0)), ('amber', (0, 1)), ('off', (0, 0)), ('partial', (None, 1))]:
        p.label(label)
        p.emit('lui', 2, 0xa004)
        for value, offset in zip(outputs, (-1872, -1876)):
            if value is not None:
                p.emit('li', 3, value)
                p.emit('sb', 3, 2, offset)
        p.emit('jr', 31)
    return p.finish()


def synthetic_hook(image, entry, values, prep):
    p = Program(entry)
    e = p.emit
    e('addiu', 29, 29, -40)
    e('sw', 31, 29, 36)
    e('sw', 17, 29, 32)
    e('sw', 16, 29, 28)
    e('cmpi', 4, 7)
    e('bteqz', 'prepare')
    e('lui', 2, values['preference'] >> 16)
    e('lbu', 2, 2, values['preference'] & 65535)
    e('li', 3, 2)
    e('li', 4, 0)
    e('and', 2, 3)
    e('bnez', 2, 'active')
    e('li', 4, 6)
    p.label('active')
    e('jal', values['led'])
    p.label('exit')
    values = dict(values, exit=p.pc)
    e('lui', 2, 0xa001)
    e('li', 3, 1)
    e('sb', 3, 2, -30000)
    e('li', 4, 150)
    e('lw', 7, 29, 36)
    e('lw', 17, 29, 32)
    e('lw', 16, 29, 28)
    e('addiu', 29, 29, 40)
    e('jr', 7)
    if (p.pc + 6) % 4: e('nop')
    p.label('prepare')
    e('jal', prep)
    e('nop')
    start = p.pc
    put(image, entry, p.finish())
    put(image, start, patterns.standby(start, values, False))
    return start, values


def synthetic_image(relocation=0, bias=0x2200, banks=1):
    image = bytearray([255]) * (banks*65536)
    header = b'PG34WCDN RTD2739 MCM999  '
    image[:len(header)] = header
    addr = {k: BASE+v+relocation for k, v in {
        'hook': 0x1000, 'policy': 0x2000, 'led': 0x2800, 'crc': 0x3000,
        'receiver': 0x3400, 'veto': 0x3900, 'cleanup': 0x3a00,
        'auxiliary': 0x3b00, 'prep': 0x3c00, 'copier': 0x3d00, 'writer': 0x3e00}.items()}
    values = {k: addr[k] for k in ('policy', 'led', 'cleanup', 'auxiliary')}
    values.update(state_upper=0xa010, state_bias=bias, preference=0xa0100000+bias+10,
                  reset_upper=0xa001, reset_first=-30000, reset_second=-30008,
                  flag_upper=0xa010, flag_offset=512)
    start, values = synthetic_hook(image, addr['hook'], values, addr['prep'])
    for k in ('veto', 'cleanup', 'auxiliary', 'prep', 'copier', 'writer'):
        put(image, addr[k], encode('jr', (31,), addr[k]))
    put(image, addr['policy'], patterns.policy(addr['policy'], 0xa010, bias+40, addr['veto']))
    put(image, addr['led'], synthetic_led(addr['led']))
    crc = patterns.crc_algorithm(addr['crc'])
    put(image, addr['crc'], crc)
    put(image, addr['crc']+len(crc), patterns.crc_compare(addr['crc']+len(crc)))
    put(image, addr['receiver'], patterns.crc_receiver(addr['receiver'], addr['crc'], addr['copier'], addr['writer'], len(image)))
    return seal(image), start, values, addr


class DiscoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original, cls.start, cls.values, cls.addr = synthetic_image()

    def corrupt(self, at, value=1):
        data = bytearray(self.original)
        data[at] ^= value
        return seal(data)

    def test_patch_synthetic_and_unchanged_surroundings(self):
        out, details = patcher.patch(self.original)
        at = self.start-BASE
        self.assertEqual(out[:at], self.original[:at])
        self.assertEqual(out[at+100:-1], self.original[at+100:-1])
        self.assertEqual(len(out), len(self.original))
        self.assertEqual(patcher.image_crc(out), out[-1])
        self.assertEqual(out[at:at+100], patterns.standby(self.start, self.values, True))
        self.assertEqual(details['static_instruction_cases'], 640)
        self.assertEqual(details['output_sha256'], patcher.sha256(out))
        for changed in details['changed_ranges']:
            start = int(changed['offset'], 0)
            self.assertEqual(self.original[start:start+changed['length']].hex(), changed['original'])
            self.assertEqual(out[start:start+changed['length']].hex(), changed['replacement'])

    def test_relocation_different_preference_and_image_length(self):
        original, start, values, _ = synthetic_image(relocation=0x4000, bias=0x2600, banks=2)
        out, details = patcher.patch(original)
        self.assertEqual(details['patch_offset'], hex(start-BASE))
        self.assertEqual(out[start-BASE:start-BASE+100], patterns.standby(start, values, True))

    def test_resource_change_without_input_hash_lock(self):
        modified_resource = self.corrupt(0xe000)
        out, details = patcher.patch(modified_resource)
        self.assertEqual(out[0xe000], modified_resource[0xe000])
        self.assertNotEqual(details['input_sha256'], patcher.sha256(self.original))

    def test_already_patched_inspection_and_refusal(self):
        out, _ = patcher.patch(self.original)
        _, report = patcher.inspect(out)
        self.assertEqual(report['status'], 'already_patched')
        with self.assertRaisesRegex(patcher.Unsupported, 'already contains'): patcher.patch(out)

    def test_bad_crc(self):
        data = bytearray(self.original)
        data[0xe000] ^= 1
        with self.assertRaisesRegex(patcher.Unsupported, 'CRC is invalid'): patcher.patch(data)

    def test_wrong_model(self):
        data = bytearray(self.original)
        data[:8] = b'PG99XXXX'
        with self.assertRaisesRegex(patcher.Unsupported, 'identity'): patcher.patch(seal(data))

    def test_wrong_scaler(self):
        data = bytearray(self.original)
        at = data.index(b'RTD2739')
        data[at:at+7] = b'RTD9999'
        with self.assertRaisesRegex(patcher.Unsupported, 'identity'): patcher.patch(seal(data))

    def test_wrong_length(self):
        with self.assertRaisesRegex(patcher.Unsupported, 'whole-bank'): patcher.patch(self.original[:-1])

    def test_changed_crc_algorithm_with_valid_image_crc(self):
        data = self.corrupt(self.addr['crc']-BASE+30)
        with self.assertRaisesRegex(patcher.Unsupported, 'CRC routine'): patcher.patch(data)

    def test_changed_crc_receiver(self):
        data = self.corrupt(self.addr['receiver']-BASE+84)
        with self.assertRaisesRegex(patcher.Unsupported, 'CRC receiver'): patcher.patch(data)

    def test_changed_crc_compare(self):
        data = self.corrupt(self.addr['crc']-BASE+52+10)
        with self.assertRaisesRegex(patcher.Unsupported, 'comparison'): patcher.patch(data)

    def test_changed_policy(self):
        data = self.corrupt(self.addr['policy']-BASE+14)
        with self.assertRaisesRegex(patcher.Unsupported, 'policy implementation'): patcher.patch(data)

    def test_changed_standby_branch(self):
        data = self.corrupt(self.start-BASE+8)
        with self.assertRaisesRegex(patcher.Unsupported, 'standby site'): patcher.patch(data)

    def test_changed_led_behavior(self):
        data = bytearray(self.original)
        code = synthetic_led(self.addr['led'])
        # Change the first emitted active-channel store from B0 to a third pin.
        store = encode('sb', (3, 2, -1872), self.addr['led'])
        at = code.index(store) + self.addr['led']-BASE
        data[at:at+len(store)] = encode('sb', (3, 2, -1868), self.addr['led'])
        with self.assertRaisesRegex(patcher.Unsupported, 'standby site'): patcher.patch(seal(data))

    def test_dead_scratch_value_becomes_live(self):
        data = bytearray(self.original)
        at = self.values['exit']-BASE
        data[at:at+4] = encode('sb', (4, 2, -30000), self.values['exit'])
        with self.assertRaisesRegex(patcher.Unsupported, 'scratch-register'): patcher.patch(seal(data))

    def test_external_direct_call_into_patch(self):
        data = bytearray(self.original)
        at = BASE + 0xe000
        put(data, at, encode('jal', (self.start+12,), at))
        with self.assertRaisesRegex(patcher.Unsupported, 'external direct call'): patcher.patch(seal(data))

    def test_absolute_pointer_into_patch(self):
        data = bytearray(self.original)
        struct.pack_into('<I', data, 0xe000, self.start+11)
        with self.assertRaisesRegex(patcher.Unsupported, 'absolute pointer'): patcher.patch(seal(data))

    def test_multiple_compatible_sites(self):
        data = bytearray(self.original)
        synthetic_hook(data, BASE+0x1800, self.values, self.addr['prep'])
        with self.assertRaisesRegex(patcher.Unsupported, 'found 2'): patcher.patch(seal(data))


class OutputTests(unittest.TestCase):
    def cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err): result = patcher.main(list(map(str, args)))
        return result, out.getvalue(), err.getvalue()

    def test_inspect_does_not_write_and_cli_patch(self):
        data, _, _, _ = synthetic_image()
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            src, dst, manifest = td/'private.bin', td/'private-patched.bin', td/'private.json'
            src.write_bytes(data)
            result, stdout, _ = self.cli('inspect', src)
            self.assertEqual(result, 0)
            self.assertEqual(json.loads(stdout)['status'], 'compatible')
            self.assertEqual(list(td.iterdir()), [src])
            result, _, err = self.cli('patch', src, dst, '--manifest', manifest)
            self.assertEqual(result, 0, err)
            self.assertEqual(src.read_bytes(), data)
            self.assertEqual(json.loads(manifest.read_text())['output_sha256'], patcher.sha256(dst.read_bytes()))
            before = dst.read_bytes()
            self.assertNotEqual(self.cli('patch', src, dst)[0], 0)
            self.assertEqual(dst.read_bytes(), before)
            self.assertNotEqual(self.cli('patch', src, src)[0], 0)

    def test_generated_files_forbidden_in_public_source_tree(self):
        source = Path('/tmp/example.bin')
        for target in (patcher.SOURCE_DIR/'example.bin', patcher.SOURCE_DIR/'nested'/'anything.json'):
            with self.assertRaisesRegex(patcher.Unsupported, 'source-only'): patcher.output_path(target, source)

    def test_same_manifest_and_output(self):
        data, _, _, _ = synthetic_image()
        with tempfile.TemporaryDirectory() as td:
            src, dst = Path(td)/'in.bin', Path(td)/'out.bin'
            src.write_bytes(data)
            self.assertNotEqual(self.cli('patch', src, dst, '--manifest', dst)[0], 0)
            self.assertFalse(dst.exists())

    def test_reservation_failure_rolls_back_binary(self):
        with tempfile.TemporaryDirectory() as td:
            dst, manifest = Path(td)/'out.bin', Path(td)/'existing.json'
            manifest.write_text('keep')
            with self.assertRaises(FileExistsError): patcher.write_outputs([(dst, b'authored test data'), (manifest, b'new')])
            self.assertFalse(dst.exists())
            self.assertEqual(manifest.read_text(), 'keep')

    def test_symlink_into_source_tree_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            link = Path(td)/'source-link'
            link.symlink_to(patcher.SOURCE_DIR, target_is_directory=True)
            with self.assertRaisesRegex(patcher.Unsupported, 'source-only'):
                patcher.output_path(link/'private.bin', Path(td)/'input.bin')


class InstructionTests(unittest.TestCase):
    def test_crc_published_algorithm_check_value(self):
        self.assertEqual(patcher.crc8(b'123456789'), 0xf4)

    def test_branches_calls_and_truncated_decoding(self):
        for op, args in [('jal', (BASE+0x2000,)), ('b', (BASE+0x1020,)),
                         ('bteqz', (BASE+0x10f0,)), ('beqz', (2, BASE+0x1000))]:
            code = encode(op, args, BASE+0x1000)
            image = bytes(0x1000)+code
            ins = decode(image, BASE+0x1000)
            self.assertEqual((ins.op, ins.args), (op, args))
        with self.assertRaises(ValueError): decode(b'', BASE)
        with self.assertRaises(ValueError): decode(b'\x00\xf0', BASE)
        with self.assertRaises(ValueError): decode(b'\x00\x18', BASE)
        with self.assertRaises(ValueError): encode('beqz', (2, BASE+0x1000), BASE)

    def test_source_tree_has_only_allowed_text_files(self):
        allowed = {'.gitignore', 'README.md', 'patcher.py', 'patterns.py', 'mips16.py', 'test_patcher.py'}
        for p in patcher.SOURCE_DIR.rglob('*'):
            if '.git' in p.parts: continue
            self.assertTrue(p.is_file() and p.parent == patcher.SOURCE_DIR and p.name in allowed,
                            f'unexpected publishable artifact: {p}')
            p.read_text(encoding='utf-8')


if __name__ == '__main__': unittest.main()
