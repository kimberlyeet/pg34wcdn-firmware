"""Authored MIPS16 subset decoder, encoder and bounded interpreter.

This is not a scaler emulator. Calls outside the selected regions are explicit
test doubles. Control transfers use the no-delay model evidenced by this image.
Contains no extracted firmware instructions or payloads.
"""
from dataclasses import dataclass
import struct

BASE = 0x86000000
REGS = (16, 17, 2, 3, 4, 5, 6, 7)
NAMES = {**{i: f'r{i}' for i in range(32)}, 2: 'v0', 3: 'v1',
         4: 'a0', 5: 'a1', 6: 'a2', 7: 'a3', 16: 's0', 17: 's1',
         24: 't8', 29: 'sp', 31: 'ra'}


def signed(v, bits):
    return v - (1 << bits) if v & (1 << (bits - 1)) else v


@dataclass(frozen=True)
class Insn:
    pc: int
    size: int
    op: str
    args: tuple

    def text(self):
        a, op = self.args, self.op
        if op in ('jal', 'b', 'bteqz', 'btnez'):
            return f'{op} 0x{a[0]:08x}'
        if op in ('beqz', 'bnez'):
            return f'{op} {NAMES[a[0]]},0x{a[1]:08x}'
        if op in ('lbu', 'sb', 'lw', 'sw'):
            return f'{op} {NAMES[a[0]]},{a[2]}({NAMES[a[1]]})'
        if op in ('li', 'lui', 'cmpi', 'sltiu'):
            return f'{op} {NAMES[a[0]]},{a[1]}'
        if op in ('addiu', 'sll', 'srl', 'sra'):
            return f'{op} {NAMES[a[0]]},{NAMES[a[1]]},{a[2]}'
        return op + (' ' + ','.join(NAMES[x] for x in a) if a else '')


def decode(image, pc):
    p = pc - BASE
    if p < 0 or p + 2 > len(image) or pc & 1:
        raise ValueError(f'invalid instruction address {pc:#x}')
    w = struct.unpack_from('<H', image, p)[0]
    ext = None
    size = 2
    if w & 0xf800 == 0xf000:
        if p + 4 > len(image):
            raise ValueError('truncated extended instruction')
        ext = w
        w = struct.unpack_from('<H', image, p + 2)[0]
        size = 4
    x, y = REGS[(w >> 8) & 7], REGS[(w >> 5) & 7]
    imm = (((ext & 31) << 11) | (ext & 0x7e0) | (w & 31)) if ext is not None else w & 255
    simm = signed(imm, 16 if ext is not None else 8)
    op, args = None, ()
    if ext is None and w & 0xfc00 == 0x1800:
        if p + 4 > len(image):
            raise ValueError('truncated call')
        low = struct.unpack_from('<H', image, p + 2)[0]
        target = ((pc + 4) & 0xf0000000) | ((w & 31) << 23) | ((w & 0x3e0) << 13) | (low << 2)
        return Insn(pc, 4, 'jal', (target,))
    if w == 0x6500:
        op = 'nop'
    elif w & 0xff00 == 0x6700:
        op, args = 'move', (REGS[(w >> 5) & 7], w & 31)
    elif w & 0xf800 == 0x6800:
        op, args = ('lui' if ext is not None and w & 32 else 'li'), (x, imm)
    elif w & 0xf800 == 0x7000:
        op, args = 'cmpi', (x, imm)
    elif w & 0xf800 == 0x5800:
        op, args = 'sltiu', (x, imm)
    elif w & 0xf800 == 0x4800:
        op, args = 'addiu', (x, x, simm)
    elif w & 0xf810 == 0x4000:
        v = signed(((ext & 15) << 11) | (ext & 0x7f0) | (w & 15), 15) if ext is not None else signed(w & 15, 4)
        op, args = 'addiu', (y, x, v)
    elif w & 0xff00 == 0x6300:
        op, args = 'addiu', (29, 29, simm if ext is not None else simm * 8)
    elif w & 0xff00 == 0x6200:
        op, args = 'sw', (31, 29, simm if ext is not None else imm * 4)
    elif w & 0xf800 in (0x9000, 0xd000):
        op, args = ('lw' if w & 0xf800 == 0x9000 else 'sw'), (x, 29, simm if ext is not None else imm * 4)
    elif w & 0xf800 in (0xa000, 0xc000):
        op, args = ('lbu' if w & 0xf800 == 0xa000 else 'sb'), (y, x, simm if ext is not None else w & 31)
    elif w & 0xf800 in (0xa800, 0xc800, 0x9800, 0xd800):
        op = {0xa800: 'lhu', 0xc800: 'sh', 0x9800: 'lw', 0xd800: 'sw'}[w & 0xf800]
        scale = 2 if op in ('lhu', 'sh') else 4
        args = (y, x, simm if ext is not None else (w & 31) * scale)
    elif w & 0xff00 in (0x6000, 0x6100):
        op, args = ('bteqz' if w & 0xff00 == 0x6000 else 'btnez'), (pc + size + 2 * simm,)
    elif w & 0xf800 in (0x2000, 0x2800):
        op, args = ('beqz' if w & 0xf800 == 0x2000 else 'bnez'), (x, pc + size + 2 * simm)
    elif w & 0xf800 == 0x1000:
        disp = simm if ext is not None else signed(w & 0x7ff, 11)
        op, args = 'b', (pc + size + 2 * disp,)
    elif w & 0xf800 == 0x3000 and w & 3 in (0, 2, 3):
        shift = (ext >> 6) & 31 if ext is not None else ((w >> 2) & 7) or 8
        op, args = {0: 'sll', 2: 'srl', 3: 'sra'}[w & 3], (x, y, shift)
    elif w & 0xf81f == 0xe800:
        op, args = 'jr', (31 if w & 32 else x,)
    elif w & 0xf81f in (0xe80a, 0xe80b, 0xe80c, 0xe80d, 0xe80e):
        op = {10: 'cmp', 11: 'neg', 12: 'and', 13: 'or', 14: 'xor'}[w & 31]
        args = (x,) if op == 'neg' else (x, y)
    elif w & 0xf803 == 0xe001:
        op, args = 'addu', (REGS[(w >> 2) & 7], x, y)
    elif w & 0xf803 == 0xe003:
        op, args = 'subu', (REGS[(w >> 2) & 7], x, y)
    elif w & 0xf81f == 0xe810:
        op, args = 'mfhi', (x,)
    elif w & 0xf81f == 0xe81b:
        op, args = 'divu', (x, y)
    elif w & 0xf81f == 0xe81a:
        op, args = 'div', (x, y)
    elif w & 0xf81f == 0xe803:
        op, args = 'sltu', (x, y)
    if op is None:
        raise ValueError(f'unsupported instruction at {pc:08x}: {w:04x} ext={ext}')
    return Insn(pc, size, op, args)


def region(image, start, end):
    result = {}
    pc = BASE + start
    while pc < BASE + end:
        ins = decode(image, pc)
        result[pc] = ins
        pc += ins.size
    if pc != BASE + end:
        raise ValueError('region ends inside instruction')
    return result


class CPU:
    def __init__(self, instructions, memory=None, stub=None):
        self.ins = instructions
        self.r = [(0x137abcdef + i * 0x10203) & 0xffffffff for i in range(32)]
        self.r[0] = 0
        self.r[29] = 0xa0200000
        self.r[31] = 0x90000001
        self.mem = dict(memory or {})
        self.stub = stub
        self.trace = []
        self.calls = []
        self.writes = []

    def run(self, start, max_steps=5000):
        r, pc = self.r, start
        for _ in range(max_steps):
            if pc == 0x90000000:
                return
            i = self.ins[pc]
            self.trace.append(pc)
            op, a, nxt = i.op, i.args, pc + i.size
            if op == 'nop':
                pass
            elif op == 'li': r[a[0]] = a[1]
            elif op == 'lui': r[a[0]] = a[1] << 16
            elif op == 'move': r[a[0]] = r[a[1]]
            elif op == 'addiu': r[a[0]] = (r[a[1]] + a[2]) & 0xffffffff
            elif op == 'sll': r[a[0]] = (r[a[1]] << a[2]) & 0xffffffff
            elif op == 'srl': r[a[0]] = r[a[1]] >> a[2]
            elif op == 'sra': r[a[0]] = (signed(r[a[1]], 32) >> a[2]) & 0xffffffff
            elif op == 'cmpi': r[24] = r[a[0]] ^ a[1]
            elif op == 'cmp': r[24] = r[a[0]] ^ r[a[1]]
            elif op == 'sltiu': r[24] = int(r[a[0]] < a[1])
            elif op == 'and': r[a[0]] &= r[a[1]]
            elif op == 'or': r[a[0]] |= r[a[1]]
            elif op == 'xor': r[a[0]] ^= r[a[1]]
            elif op == 'neg': r[a[0]] = -r[a[0]] & 0xffffffff
            elif op == 'addu': r[a[0]] = (r[a[1]] + r[a[2]]) & 0xffffffff
            elif op == 'subu': r[a[0]] = (r[a[1]] - r[a[2]]) & 0xffffffff
            elif op in ('lbu', 'lhu', 'lw', 'sb', 'sh', 'sw'):
                addr = (r[a[1]] + a[2]) & 0xffffffff
                n = 4 if op in ('lw', 'sw') else 2 if op in ('lhu', 'sh') else 1
                if op in ('lbu', 'lhu', 'lw'):
                    r[a[0]] = sum(self.mem.get(addr + k, 0) << (8 * k) for k in range(n))
                else:
                    for k in range(n): self.mem[addr + k] = r[a[0]] >> (8 * k) & 255
                    self.writes.append((addr, n, r[a[0]] & ((1 << (8 * n)) - 1)))
            elif op == 'b': nxt = a[0]
            elif op in ('beqz', 'bnez'):
                if (r[a[0]] == 0) == (op == 'beqz'): nxt = a[1]
            elif op in ('bteqz', 'btnez'):
                if (r[24] == 0) == (op == 'bteqz'): nxt = a[0]
            elif op == 'jr': nxt = r[a[0]] & ~1
            elif op == 'jal':
                r[31] = nxt | 1
                self.calls.append((pc, a[0], tuple(r[4:8])))
                if a[0] in self.ins: nxt = a[0]
                elif self.stub: self.stub(self, a[0])
                else: raise ValueError(f'unmodelled call {a[0]:08x}')
            else: raise ValueError(op)
            pc = nxt
        raise RuntimeError('step limit')


def encode(op, args, pc):
    """Encode the small subset needed to author the patch and synthetic tests."""
    def reg(n):
        if n not in REGS:
            raise ValueError(f'register cannot be compressed: {n}')
        return REGS.index(n)

    def words(*values):
        return struct.pack('<' + 'H' * len(values), *values)

    def immediate(word, value, short=False):
        if short:
            return words(word | (value & 255))
        if not -32768 <= value <= 65535:
            raise ValueError('immediate exceeds 16 bits')
        v = value & 65535
        return words(0xf000 | ((v >> 11) & 31) | (v & 0x7e0), word | (v & 31))

    if op == 'nop': return words(0x6500)
    if op == 'jal':
        target, = args
        if target & 1 or (pc + 4) >> 28 != target >> 28:
            raise ValueError('unaligned/out-of-region JAL')
        index = (target & 0x0fffffff) >> 2
        high = index >> 16
        if target & 2:
            raise ValueError('JAL target must be word aligned')
        return words(0x1800 | ((high & 31) << 5) | (high >> 5), index & 65535)
    if op in ('b', 'beqz', 'bnez', 'bteqz', 'btnez'):
        target = args[-1]
        delta = target - (pc + 2)
        limit = 1024 if op == 'b' else 128
        if delta % 2 or not -limit <= delta // 2 < limit:
            raise ValueError('short branch cannot reach target')
        word = {'b': 0x1000, 'beqz': 0x2000, 'bnez': 0x2800,
                'bteqz': 0x6000, 'btnez': 0x6100}[op]
        if op in ('beqz', 'bnez'): word |= reg(args[0]) << 8
        return words(word | ((delta // 2) & (2047 if op == 'b' else 255)))
    if op == 'jr': return words(0xe820 if args[0] == 31 else 0xe800 | reg(args[0]) << 8)
    if op == 'move': return words(0x6700 | reg(args[0]) << 5 | args[1])
    if op in ('li', 'lui', 'cmpi', 'sltiu'):
        x, value = args
        word = {'li': 0x6800, 'lui': 0x6820, 'cmpi': 0x7000, 'sltiu': 0x5800}[op] | reg(x) << 8
        return immediate(word, value, op != 'lui' and 0 <= value < 256)
    if op in ('and', 'or', 'xor', 'cmp', 'neg'):
        code = {'cmp': 10, 'neg': 11, 'and': 12, 'or': 13, 'xor': 14}[op]
        return words(0xe800 | reg(args[0]) << 8 | (reg(args[0] if op == 'neg' else args[1]) << 5) | code)
    if op == 'addiu':
        dst, src, v = args
        if dst == src == 29:
            if v % 8 or not -1024 <= v <= 1016: raise ValueError('stack immediate')
            return words(0x6300 | ((v // 8) & 255))
        if dst == src:
            return immediate(0x4800 | reg(dst) << 8, v, -128 <= v < 128)
        if not -16384 <= v <= 16383: raise ValueError('15-bit immediate')
        v &= 32767
        return words(0xf000 | (v >> 11) | (v & 0x7f0),
                     0x4000 | reg(src) << 8 | reg(dst) << 5 | (v & 15))
    if op in ('lbu', 'lhu', 'lw', 'sb', 'sh', 'sw'):
        value, base, offset = args
        if base == 29 and op in ('lw', 'sw') and 0 <= offset < 1024 and offset % 4 == 0:
            if op == 'sw' and value == 31: return words(0x6200 | offset // 4)
            return words((0x9000 if op == 'lw' else 0xd000) | reg(value) << 8 | offset // 4)
        code = {'lbu': 0xa000, 'lhu': 0xa800, 'lw': 0x9800,
                'sb': 0xc000, 'sh': 0xc800, 'sw': 0xd800}[op]
        word = code | reg(base) << 8 | reg(value) << 5
        scale = 1 if op in ('lbu', 'sb') else 2 if op in ('lhu', 'sh') else 4
        if 0 <= offset < 32 * scale and offset % scale == 0: return words(word | offset // scale)
        return immediate(word, offset)
    if op in ('sll', 'srl', 'sra'):
        dst, src, shift = args
        if not 1 <= shift <= 31: raise ValueError('shift')
        code = {'sll': 0, 'srl': 2, 'sra': 3}[op]
        word = 0x3000 | reg(dst) << 8 | reg(src) << 5 | code
        return words(word | (shift % 8) << 2) if shift <= 8 else words(0xf000 | shift << 6, word)
    if op in ('addu', 'subu'):
        dst, x, y = args
        return words(0xe000 | reg(x) << 8 | reg(y) << 5 | reg(dst) << 2 | (1 if op == 'addu' else 3))
    if op == 'mfhi': return words(0xe810 | reg(args[0]) << 8)
    if op in ('divu', 'div', 'sltu'):
        return words({'divu': 0xe81b, 'div': 0xe81a, 'sltu': 0xe803}[op] | reg(args[0]) << 8 | reg(args[1]) << 5)
    raise ValueError(f'cannot encode {op}')


class Program:
    """Author instructions with labels, using only short branches."""
    def __init__(self, pc):
        self.start = self.pc = pc
        self.items, self.labels = [], {}

    def label(self, name):
        if name in self.labels: raise ValueError('duplicate label')
        self.labels[name] = self.pc

    def emit(self, op, *args):
        self.items.append((self.pc, op, args))
        self.pc += 2 if op in ('b', 'bteqz', 'btnez', 'beqz', 'bnez') else len(encode(op, args, self.pc))

    def finish(self):
        out = bytearray()
        for pc, op, args in self.items:
            resolved = tuple(self.labels[a] if isinstance(a, str) else a for a in args)
            out.extend(encode(op, resolved, pc))
        return bytes(out)
