#!/usr/bin/env python3
"""Discover and patch compatible ASUS PG34WCDN indicator firmware. Offline only."""
import sys
sys.dont_write_bytecode = True

import argparse
from dataclasses import dataclass
import hashlib
import itertools
import json
from pathlib import Path
import re
import struct

from mips16 import BASE, CPU, Insn, decode, encode, region
import patterns

SOURCE_DIR = Path(__file__).resolve().parent
GPIO = (0xa003f8b0, 0xa003f8ac)


class Unsupported(ValueError):
    pass


def require(condition, message):
    if not condition: raise Unsupported(message)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def crc8(data, initial=0):
    table = []
    for c in range(256):
        for _ in range(8): c = ((c << 1) ^ (7 if c & 128 else 0)) & 255
        table.append(c)
    c = initial
    for value in data: c = table[c ^ value]
    return c


def image_crc(data):
    return crc8(data[:-1] + b'\xff')


def sequence(data, pc, count):
    out = []
    for _ in range(count):
        i = decode(data, pc)
        out.append(i)
        pc += i.size
    return out


def expect(i, op, args=None):
    require(i.op == op and (args is None or i.args == args), f'unrecognized instruction at {i.pc:#x}')
    return i.args


def code_address(data, pc):
    require(BASE <= pc < BASE + len(data) - 4 and pc % 2 == 0,
            f'call/branch target outside image: {pc:#x}')


def starts(data, first):
    """Look for a single authored instruction, not a stored firmware signature."""
    needle = encode(first[0], first[1], BASE)
    at = data.find(needle)
    while at != -1:
        if at % 2 == 0: yield BASE + at
        at = data.find(needle, at + 1)


def same(data, pc, authored):
    return 0 <= pc - BASE <= len(data) - len(authored) and data[pc-BASE:pc-BASE+len(authored)] == authored


def find_integrity(data):
    crcs = [pc for pc in starts(data, ('move', (2, 6))) if same(data, pc, patterns.crc_algorithm(pc))]
    require(len(crcs) == 1, f'expected one recognized CRC routine, found {len(crcs)}')
    crc = crcs[0]
    compares = [pc for pc in starts(data, ('lui', (2, 0xa010))) if same(data, pc, patterns.crc_compare(pc))]
    require(len(compares) == 1, 'CRC completion comparison not uniquely recognized')
    receivers = []
    for pc in starts(data, ('addiu', (29, 29, -32))):
        try:
            copier = expect(decode(data, pc + 40), 'jal')[0]
            writer = expect(decode(data, pc + 124), 'jal')[0]
            code_address(data, copier)
            code_address(data, writer)
            if same(data, pc, patterns.crc_receiver(pc, crc, copier, writer, len(data))): receivers.append(pc)
        except (ValueError, struct.error):
            continue
    require(len(receivers) == 1, f'expected one recognized image-CRC receiver, found {len(receivers)}')
    return {'crc_routine': crc, 'crc_receiver': receivers[0], 'crc_compare': compares[0]}


def leaf(data, start):
    """Recover the LED leaf CFG and reject unrecognized transfers or calls."""
    pending, ins = [start], {}
    while pending:
        pc = pending.pop()
        if pc in ins: continue
        require(start <= pc < start + 512 and len(ins) < 128, 'LED leaf exceeds bounded region')
        i = decode(data, pc)
        require(i.op not in ('jal', 'div', 'divu', 'mfhi'), 'LED target is not a recognized leaf')
        ins[pc] = i
        if i.op == 'jr':
            require(i.args == (31,), 'LED leaf has nonstandard return')
        elif i.op == 'b': pending.append(i.args[0])
        else:
            pending.append(pc + i.size)
            if i.op in ('beqz', 'bnez', 'bteqz', 'btnez'): pending.append(i.args[-1])
    occupied = set()
    for pc, i in ins.items():
        for a in range(pc, pc + i.size, 2):
            require(a not in occupied, 'overlapping LED instructions')
            occupied.add(a)
    for mode, b0, ac in itertools.product(range(256), (0, 1), (0, 1)):
        c = CPU(ins, dict(zip(GPIO, (b0, ac))))
        c.r[4] = mode
        saved = tuple(c.r[r] for r in (*range(16, 24), 28, 29, 30, 31))
        c.run(start)
        require(saved == tuple(c.r[r] for r in (*range(16, 24), 28, 29, 30, 31)),
                'LED selector changes preserved registers')
        expected = ((1, 0) if mode in (0, 2, 4, 7) else (0, 1) if mode in (3, 5)
                    else (0, 0) if mode in (6, 13) else (b0, 1) if mode == 8 else (b0, ac))
        require(tuple(c.mem[a] for a in GPIO) == expected, 'LED selector output contract differs')
        require(all(a in GPIO and n == 1 for a, n, _ in c.writes), 'LED leaf writes unexpected memory')
        require(all(i.op not in ('lbu', 'lhu', 'lw') for i in ins.values()), 'LED leaf reads unmodeled memory')
    return ins


def context(data, start, led):
    for entry in range(max(BASE, start - 2048), start, 2):
        try:
            head = sequence(data, entry, 4)
            required = [('addiu', (29, 29, -40)), ('sw', (31, 29, 36)),
                        ('sw', (17, 29, 32)), ('sw', (16, 29, 28))]
            if [(i.op, i.args) for i in head] != required: continue
            ins = region(data, entry - BASE, start - BASE + 100)
            epilogue = [('lw', (7, 29, 36)), ('lw', (17, 29, 32)),
                        ('lw', (16, 29, 28)), ('addiu', (29, 29, 40)), ('jr', (7,))]
            if not any([(x.op, x.args) for x in sequence(data, i.pc, 5)] == epilogue
                       for i in ins.values() if i.op == 'lw' and i.args == (7, 29, 36)):
                continue
            action7 = any(i.op == 'cmpi' and i.args == (4, 7)
                          and ins.get(i.pc+i.size, Insn(0, 0, '', ())).op == 'bteqz'
                          and ins[i.pc+i.size].args == (start-6,) for i in ins.values())
            if not action7: continue
            preferences = set()
            for i in ins.values():
                if i.op != 'lui' or i.args[0] != 2: continue
                following = ins.get(i.pc + i.size)
                if following is None or following.op != 'lbu' or following.args[:2] != (2, 2): continue
                s = sequence(data, i.pc, 8)
                if not (s[1].op == 'lbu' and s[1].args[:2] == (2, 2)): continue
                if [(x.op, x.args) for x in s[2:5]] != [
                    ('li', (3, 2)), ('li', (4, 0)), ('and', (2, 3))]: continue
                if s[5].op != 'bnez' or s[5].args != (2, s[7].pc): continue
                if (s[6].op, s[6].args, s[7].op, s[7].args) != ('li', (4, 6), 'jal', (led,)): continue
                preferences.add((i.args[1] << 16) + s[1].args[2])
            if len(preferences) == 1: return entry, ins, preferences.pop()
        except (ValueError, struct.error):
            continue
    raise Unsupported('action-7 hook and independent normal/wake preference check not recognized')


def no_a0_read_before_overwrite(ins, exit_pc):
    # The removed scratch calculations must have no reader at the continuation.
    pc = exit_pc
    for _ in range(16):
        require(pc in ins, 'exit outside verified hook')
        i = ins[pc]
        if i.op in ('li', 'lui') and i.args[0] == 4: return
        if i.op in ('lbu', 'lhu', 'lw'):
            reads = (i.args[1],)
        elif i.op in ('li', 'lui', 'nop'):
            reads = ()
        elif i.op in ('sb', 'sh', 'sw'):
            reads = i.args[:2]
        else:
            raise Unsupported('exit scratch-register liveness cannot be established')
        require(4 not in reads, 'exit reads a removed scratch-register value')
        pc += i.size
    raise Unsupported('scratch-register liveness check exceeded bound')


def candidate(data, start):
    a = decode(data, start + 8)
    expect(a, 'bteqz')
    patched = a.args == (start + 26,)
    require(patched or a.args == (start + 12,), 'unrecognized LED-selection control flow')
    delta = 14 if patched else 0
    v = {
        'policy': expect(decode(data, start), 'jal')[0],
        'led': expect(decode(data, start+12+delta), 'jal')[0],
        'cleanup': expect(decode(data, start+16+delta), 'jal')[0],
        'auxiliary': expect(decode(data, start+22+delta), 'jal')[0],
        'state_upper': expect(decode(data, start+28+delta), 'lui')[1],
        'state_bias': expect(decode(data, start+32+delta), 'addiu')[2],
        'exit': expect(decode(data, start+98), 'b')[0],
    }
    shift = 8 if patched else 0
    v.update(reset_upper=expect(decode(data, start+66+shift), 'lui')[1],
             reset_first=expect(decode(data, start+(80 if patched else 78)), 'sb')[2],
             reset_second=expect(decode(data, start+(84 if patched else 74)), 'sb' if patched else 'addiu')[-1],
             flag_upper=expect(decode(data, start+(88 if patched else 84)), 'lui')[1],
             flag_offset=expect(decode(data, start+94), 'sb')[2])
    expect(decode(data, start-6), 'jal')
    expect(decode(data, start-2), 'nop', ())
    for key in ('policy', 'led', 'cleanup', 'auxiliary', 'exit'): code_address(data, v[key])
    entry, ins, v['preference'] = context(data, start, v['led'])
    require(0xa0100020 <= v['preference'] < 0xa0108000, 'unsupported preference RAM address')
    require((v['state_upper'] << 16) + v['state_bias'] + 10 == v['preference'],
            'standby state block does not agree with normal/wake preference address')
    require(v['state_upper'] == v['flag_upper'] == 0xa010 and v['reset_upper'] == 0xa001,
            'unexpected RAM regions')
    authored = patterns.standby(start, v, patched)
    require(len(authored) == 100 and same(data, start, authored), 'standby instruction structure differs')
    no_a0_read_before_overwrite(ins, v['exit'])
    for pc, i in ins.items():
        if i.op in ('b', 'beqz', 'bnez', 'bteqz', 'btnez'):
            target = i.args[-1]
            require(target in ins, 'hook branch into unsupported region or instruction interior')
            require(not (start < target < start+100 and not start <= pc < start+100),
                    'another hook path enters rewritten instructions')
    s = sequence(data, v['policy'], 16)
    upper, offset, veto = expect(s[3], 'lui')[1], expect(s[4], 'lbu')[2], expect(s[8], 'jal')[0]
    require(upper == 0xa010 and 0 <= offset < 32768, 'unsupported policy RAM address')
    code_address(data, veto)
    require(same(data, v['policy'], patterns.policy(v['policy'], upper, offset, veto)),
            'separate policy implementation not recognized')
    led_ins = leaf(data, v['led'])
    return Plan(start, entry, v, patched, led_ins, (upper << 16) + offset, veto)


@dataclass
class Plan:
    start: int
    hook: int
    values: dict
    already_patched: bool
    led_instructions: dict
    policy_byte: int
    policy_veto: int


def inbound_checks(data, plan):
    start, end = plan.start, plan.start + 100
    for at, (w,) in enumerate(struct.iter_unpack('<H', data)):
        if w & 0xfc00 != 0x1800 or at*2+4 > len(data): continue
        pc = BASE + at*2
        target = decode(data, pc).args[0]
        require(not start < target < end or start <= pc < end, 'external direct call into patch interior')
    for target in range(start+2, end, 2):
        for tagged in (target, target | 1):
            require(struct.pack('<I', tagged) not in data, 'absolute pointer into patch interior')


def discover(data):
    require(65536 <= len(data) <= 16*1024*1024 and len(data) % 65536 == 0,
            'expected a flat, whole-bank firmware image between 64 KiB and 16 MiB')
    require(b'PG34WCDN' in data and b'RTD2739' in data, 'PG34WCDN/RTD2739 identity not found')
    require(image_crc(data) == data[-1], 'image CRC is invalid; input may be corrupt or unsupported')
    integrity = find_integrity(data)
    plans = []
    reasons = []
    for pc in starts(data, ('cmpi', (2, 1))):
        start = pc - 4
        try:
            if decode(data, start).op != 'jal': continue
            if (decode(data, pc+2).op, decode(data, pc+2).args) != ('li', (4, 13)): continue
            plans.append(candidate(data, start))
        except (ValueError, struct.error, KeyError, RuntimeError) as e:
            reasons.append(str(e))
    require(len(plans) == 1, f'expected one compatible standby site, found {len(plans)}' +
            (f'; details: {"; ".join(dict.fromkeys(reasons))}' if reasons else ''))
    inbound_checks(data, plans[0])
    return plans[0], integrity


def verify_rewrite(data, plan, replacement):
    start, v = plan.start, plan.values
    original = patterns.standby(start, v, False)
    buffers = []
    for block in (original, replacement):
        copy = bytearray(data)
        copy[start-BASE:start-BASE+100] = block
        ins = region(copy, start-BASE, start-BASE+100)
        ins.update(plan.led_instructions)
        policy_bytes = patterns.policy(v['policy'], plan.policy_byte >> 16, plan.policy_byte & 65535, plan.policy_veto)
        ins.update(region(copy, v['policy']-BASE, v['policy']-BASE+len(policy_bytes)))
        ins[v['exit']] = Insn(v['exit'], 2, 'jr', (30,))  # stop marker, never written to firmware
        buffers.append(ins)
    flag_cases = [(0xbf | bit*64, 0xf8 | low, 0xfb | bit2*4)
                  for bit, low, bit2 in itertools.product((0, 1), range(8), (0, 1))]
    cases = itertools.chain(itertools.product(range(256), (0, 1), [(0, 0, 0)]),
                            itertools.product((0, 2), (0, 1), flag_cases))
    count = 0
    for pref, policy_result, (d, e, m) in cases:
        state = (v['state_upper'] << 16) + v['state_bias']
        initial = {v['preference']: pref, state+13: d, state+14: e, state+23: m,
                   plan.policy_byte: 2, GPIO[0]: 1, GPIO[1]: 1}
        outputs = []
        for ins in buffers:
            def stub(c, target):
                require(target in (plan.policy_veto, v['cleanup'], v['auxiliary']), 'unmodeled block call')
                for reg in (2, 3, 4, 5, 6, 7, 24): c.r[reg] = (target + reg) & 0xffffffff
                c.r[2] = (1 - policy_result) if target == plan.policy_veto else 0
            c = CPU(ins, initial, stub)
            c.r[30] = 0x90000001
            saved = tuple(c.r[r] for r in (16, 17, 29))
            c.run(start)
            require(saved == tuple(c.r[r] for r in (16, 17, 29)), 'callee-saved state changed')
            calls = [(target, args[:1] if target in (v['led'], v['auxiliary']) else ())
                     for _, target, args in c.calls]
            writes = [(a, n, value) for a, n, value in c.writes if not 0xa01fff00 <= a < 0xa0200000]
            outputs.append((c, calls, writes))
        old, new = outputs
        require([(t, a) for t, a in old[1] if t != v['led']] ==
                [(t, a) for t, a in new[1] if t != v['led']], 'non-LED calls changed')
        require([w for w in old[2] if w[0] not in GPIO] == [w for w in new[2] if w[0] not in GPIO],
                'non-LED writes changed')
        if pref & 2: require(old[1:] == new[1:], 'enabled-preference behavior changed')
        expected = (0, 0 if not pref & 2 or policy_result == 1 else 1)
        require(tuple(new[0].mem[a] for a in GPIO) == expected, 'incorrect indicator outputs')
        count += 1
    return count


def inspect(data):
    plan, integrity = discover(data)
    versions = sorted({v.decode('ascii') for v in re.findall(rb'MCM[0-9]{3}', data)})
    details = {'status': 'already_patched' if plan.already_patched else 'compatible',
               'model': 'PG34WCDN', 'firmware_labels': versions,
               'input_sha256': sha256(data), 'image_size': len(data),
               'patch_offset': hex(plan.start-BASE), 'hook_offset': hex(plan.hook-BASE),
               'discovered_addresses': {k: hex(v) for k, v in plan.values.items()},
               'integrity': {k: hex(v) for k, v in integrity.items()},
               'crc_field_offset': hex(len(data)-1), 'crc': f'{data[-1]:02X}',
               'validation': 'structural recognition and bounded static checks; no hardware/updater test'}
    return plan, details


def patch(data):
    plan, details = inspect(data)
    require(not plan.already_patched, 'input already contains this patch')
    replacement = patterns.standby(plan.start, plan.values, True)
    require(len(replacement) == 100, 'replacement cannot fit in place')
    cases = verify_rewrite(data, plan, replacement)
    at = plan.start - BASE
    expected = patterns.standby(plan.start, plan.values, False)
    require(data[at:at+100] == expected, 'input instruction precondition changed')
    out = bytearray(data)
    out[at:at+100] = replacement
    out[-1] = image_crc(out)
    require(len(out) == len(data) and image_crc(out) == out[-1], 'output size/CRC failure')
    require(out[:at] == data[:at] and out[at+100:-1] == data[at+100:-1], 'unexpected output change')
    ranges = []
    for i, (old, new) in enumerate(zip(data, out)):
        if old == new: continue
        if ranges and ranges[-1][1] == i: ranges[-1][1] = i+1
        else: ranges.append([i, i+1])
    details.update(status='patched', output_sha256=sha256(out), static_instruction_cases=cases,
                   changed_byte_count=sum(e-s for s, e in ranges), output_crc=f'{out[-1]:02X}',
                   changed_ranges=[{'offset': hex(s), 'length': e-s,
                                    'original': data[s:e].hex(), 'replacement': bytes(out[s:e]).hex()}
                                   for s, e in ranges])
    return bytes(out), details


def output_path(path, source):
    path = path.resolve()
    require(not path.is_relative_to(SOURCE_DIR), 'generated files must be outside the source-only patcher folder')
    require(path != source.resolve(), 'input and output must differ')
    require(not path.exists(), f'refusing to overwrite {path}')
    return path


def write_outputs(paths_and_bytes):
    """Reserve all files exclusively; roll back our files if any write fails."""
    created = []
    try:
        for path, content in paths_and_bytes:
            f = path.open('xb')
            created.append((path, f))
        for (_, f), (_, content) in zip(created, paths_and_bytes): f.write(content)
        for _, f in created: f.close()
    except BaseException:
        for path, f in created:
            f.close()
            path.unlink(missing_ok=True)
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest='command', required=True)
    show = subs.add_parser('inspect', help='check compatibility without writing files')
    show.add_argument('input', type=Path)
    build = subs.add_parser('patch', help='write a separate patched firmware outside this folder')
    build.add_argument('input', type=Path)
    build.add_argument('output', type=Path)
    build.add_argument('--manifest', type=Path)
    args = parser.parse_args(argv)
    try:
        # Avoid reading arbitrarily large files before the format limit is checked.
        require(args.input.stat().st_size <= 16*1024*1024, 'image exceeds supported format size')
        data = args.input.read_bytes()
        if args.command == 'inspect':
            _, details = inspect(data)
        else:
            output = output_path(args.output, args.input)
            manifest = output_path(args.manifest, args.input) if args.manifest else None
            require(manifest != output, 'manifest and firmware output must differ')
            result, details = patch(data)
            files = [(output, result)]
            if manifest: files.append((manifest, (json.dumps(details, indent=2)+'\n').encode()))
            write_outputs(files)
        print(json.dumps(details, indent=2))
        return 0
    except (OSError, ValueError, struct.error, KeyError, RuntimeError) as e:
        print(f'error: {e}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
