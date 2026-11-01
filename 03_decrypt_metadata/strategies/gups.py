"""
gups.py - GUPS AntiCheat Metadata Decryption Strategy
Supports profile-based XOR recovery and generic structural search with token validators.
"""

import os
import struct
from collections import Counter

MAGIC = 0xFAB11BAF
HDR_SIZE = 0x150
N_SECTIONS = 31

SECTION_NAMES = [
    "stringLiteral", "stringLiteralData", "string", "events", "properties", "methods",
    "parameterDefaultValues", "fieldDefaultValues", "fieldAndParameterDefaultValueData",
    "fieldMarshaledSizes", "parameters", "fields", "genericParameters",
    "genericParameterConstraints", "genericContainers", "nestedTypes", "interfaces",
    "vtableMethods", "interfaceOffsets", "typeDefinitions", "images", "assemblies", "fieldRefs",
    "referencedAssemblies", "attributeData", "attributeDataRange",
    "unresolvedVirtualCallParameterTypes", "unresolvedVirtualCallParameterRanges",
    "windowsRuntimeTypeNames", "windowsRuntimeStrings", "exportedTypeDefinitions",
]

REC_V31 = [
    8, 0, 0, 24, 20, 36, 12, 12, 0, 12, 12, 12, 16, 4, 16, 4, 4, 4, 8, 88, 40, 64, 8, 4, 0,
    8, 4, 8, 8, 0, 4
]

TOKEN_CHECKS = {
    3: (20, 0x14),   # event token
    4: (16, 0x17),   # property token
    5: (24, 0x06),   # method token
    10: (4, 0x08),   # parameter token
    11: (8, 0x04),   # field token
    19: (84, 0x02),  # typedef token
    21: (4, 0x20),   # assembly token
}

PROFILE_49 = {
    "header_key": 0x62,
    "slots": [58, 0, 75, 62, 49, 78, 39, 45, 44, 35, 57, 37, 5, 20, 48, 72, 46, 83, 47, 12, 33, 24,
              70, 31, 51, 6, 1, 15, 54, 79, 7],
    "keys": {0: 0x74, 1: 0xB4, 2: 0xEC, 4: 0xEC, 5: 0xDC, 11: 0xEC, 21: 0xDC},
}


class Blob:
    def __init__(self, data):
        self.d = data
        self.n = len(data)

    def read(self, pos, size, B):
        b = self.d[pos:pos + size]
        if B is None:
            return bytes(b)
        return bytes(x ^ ((pos + i + B) & 0xFF) for i, x in enumerate(b))

    def u32(self, pos, B):
        b = self.read(pos, 4, B)
        return struct.unpack("<I", b)[0] if len(b) == 4 else None

    def ramp_key(self, pos, size=0x400):
        blk = self.d[pos:pos + size]
        if len(blk) < 16:
            return None
        c = Counter(((x - (pos + i)) & 0xFF) for i, x in enumerate(blk))
        B, f = c.most_common(1)[0]
        zeros = blk.count(0)
        return B if f > max(0.10 * len(blk), zeros) else None


def ident_score(buf):
    parts = buf.split(b"\0")
    good = total = 0
    for p in parts:
        if not p:
            continue
        total += 1
        if all(32 <= ch < 127 for ch in p) and any(65 <= (ch & 0xDF) <= 90 for ch in p):
            good += 1
    return good / total if total else 0.0


def printable_score(buf):
    if not buf:
        return 0.0
    return sum(1 for ch in buf if 32 <= ch < 127 or ch in (9, 10, 13)) / len(buf)


def walk_string_literals(blob, start):
    best = None
    cands = [blob.ramp_key(start), None] + list(range(256))
    seen = set()
    for B in cands:
        if B in seen:
            continue
        seen.add(B)
        p, run, n = start, 0, 0
        while p + 8 <= blob.n:
            b = blob.read(p, 8, B)
            ln, idx = struct.unpack("<II", b)
            if idx != run or ln > 0x100000:
                break
            run += ln
            n += 1
            p += 8
        if n > 100 and (best is None or n > best[1]):
            best = (B, n, p - start, run)
            if B == cands[0]:
                break
    return best


ANDROID_EMPTY = {28, 29}
MIN_OPTIONAL_SECTION = 22
MONOTONIC_FIELD0 = {6, 7, 9, 12, 22, 27}
INDEX_ARRAYS = {13, 15, 16, 23, 26, 30}


class Solver:
    def __init__(self, blob, rec_sizes):
        self.b = blob
        self.rec = rec_sizes
        self._text_key = {}
        self._ok_cache = {}

    def text_key(self, start, size):
        if start in self._text_key:
            return self._text_key[start]
        n = min(size, 0x1000)
        blk = self.b.d[start:start + n]
        mode = Counter(((x - (start + i)) & 0xFF) for i, x in enumerate(blk)).most_common(1)[0][0]
        best = max(((ident_score(self.b.read(start, n, B)), B) for B in (None, mode)),
                   key=lambda t: t[0])
        if best[0] < 0.85:
            for B in range(256):
                sc = ident_score(self.b.read(start, n, B))
                if sc > best[0]:
                    best = (sc, B)
        self._text_key[start] = best
        return best

    def ok(self, idx, start, size):
        key = (idx, start, size)
        r = self._ok_cache.get(key)
        if r is None:
            r = self._ok_cache[key] = self._ok(idx, start, size)
        return r

    def _ok(self, idx, start, size):
        b, rec = self.b, self.rec[idx]
        if size == 0:
            return True
        if (rec and size % rec) or start + size > b.n:
            return False
        if idx == 2:
            return self.text_key(start, size)[0] > 0.85
        B = b.ramp_key(start, min(size, 0x400)) if size >= 64 else None
        keys = [B, None] if B is not None else [None]
        n = min(16, size // rec) if rec else 0
        for K in keys:
            if idx in TOKEN_CHECKS:
                off, hi = TOKEN_CHECKS[idx]
                good = all((b.u32(start + k * rec + off, K) or 0) >> 24 == hi for k in range(min(n, 8)))
            elif idx in MONOTONIC_FIELD0:
                f0 = [b.u32(start + k * rec, K) for k in range(n)]
                good = f0 == sorted(f0) and f0[-1] < 0x1000000
            elif idx in INDEX_ARRAYS:
                good = all(b.u32(start + 4 * k, K) < 0x1000000 for k in range(n))
            elif idx == 14:
                good = all(b.u32(start + 16 * k + 8, K) in (0, 1) for k in range(min(n, 8)))
            elif idx == 25:
                offs = [b.u32(start + 8 * k + 4, K) for k in range(n)]
                good = offs == sorted(offs) and offs[0] == 0
            else:
                good = True
            if good:
                return True
        return False

    def _u32s(self, start, size, rec, field, n=None):
        B = self.b.ramp_key(start, min(size, 0x400)) if size >= 64 else None
        cnt = size // rec if n is None else min(n, size // rec)
        return [self.b.u32(start + k * rec + field, B) for k in range(cnt)]

    def consistent(self, lay):
        (o19, s19), (o20, s20), (o21, s21) = lay[19], lay[20], lay[21]
        if s20 // 40 != s21 // 64:
            return False
        o24, s24 = lay[24]
        o25, s25 = lay[25]
        if s25:
            last = self._u32s(o25 + s25 - 8, 8, 8, 4)[0]
            if last > s24:
                return False
        o26, s26 = lay[26]
        o27, s27 = lay[27]
        if bool(s26) != bool(s27):
            return False
        if s27:
            st, ln = self._u32s(o27 + s27 - 8, 8, 8, 0)[0], self._u32s(o27 + s27 - 8, 8, 8, 4)[0]
            if st + ln != s26 // 4:
                return False
        img = [self._u32s(o20, s20, 40, f) for f in (8, 12, 16, 20)]
        if max(a + c for a, c in zip(img[0], img[1])) != s19 // 88:
            return False
        exp_end = max((a + c for a, c in zip(img[2], img[3]) if a != 0xFFFFFFFF), default=0)
        if exp_end * 4 != lay[30][1]:
            return False
        return True

    def solve(self, cand_sizes, start_idx=0, start_pos=HDR_SIZE, prefix=(), pool=None,
              node_budget=1_000_000, pads=(0, 4, 8, 12), anchors=None, anchor_win=0x80,
              max_solutions=5000):
        import bisect
        used_anchor = set()

        def take_anchor(pos):
            if anchors is None:
                return -1
            k = bisect.bisect_left(anchors, pos - anchor_win)
            while k < len(anchors) and anchors[k] <= pos + anchor_win:
                if k not in used_anchor:
                    return k
                k += 1
            return None

        sols = []
        nodes = [0]
        b = self.b

        def done():
            return nodes[0] > node_budget or len(sols) >= max_solutions

        def rec(i, pos, acc):
            if done():
                return
            nodes[0] += 1
            if i == N_SECTIONS:
                if pos <= b.n and b.n - pos <= 0x10000 and self.consistent(acc):
                    pad_total = sum(acc[k][0] - acc[k - 1][0] - acc[k - 1][1] for k in range(1, len(acc)))
                    sols.append((pad_total, b.n - pos, list(acc)))
                return
            for pad in pads:
                st = pos + pad
                for s in cand_sizes[i]:
                    if pool is not None and pool[s] <= 0:
                        continue
                    if st + s > b.n or (s == 0 and (i < MIN_OPTIONAL_SECTION or pad)):
                        continue
                    anc = -1
                    if i + 1 < N_SECTIONS and s:
                        anc = take_anchor(st + s)
                        if anc is None:
                            continue
                    if not self.ok(i, st, s):
                        continue
                    if pool is not None:
                        pool[s] -= 1
                    if anc >= 0:
                        used_anchor.add(anc)
                    acc.append((st, s))
                    rec(i + 1, st + s, acc)
                    acc.pop()
                    if anc >= 0:
                        used_anchor.discard(anc)
                    if pool is not None:
                        pool[s] += 1
                    if done():
                        return

        rec(start_idx, start_pos, list(prefix))
        lay = min(sols, key=lambda t: t[:2])[2] if sols else None
        if lay:
            lay = normalize_pads(lay, self.rec)
        return lay, nodes[0]


def normalize_pads(layout, rec_sizes):
    lay = list(layout)
    for i in range(1, len(lay)):
        prev_o, prev_s = lay[i - 1]
        gap = lay[i][0] - (prev_o + prev_s)
        if gap and rec_sizes[i - 1] == 0 and prev_s and i >= 2:
            lay[i - 1] = (prev_o + gap, prev_s)
    return lay


def decode_header(blob, C):
    raw = bytes(blob.d[p] ^ ((C - p) & 0xFF) for p in range(HDR_SIZE))
    return list(struct.unpack("<%dI" % (HDR_SIZE // 4), raw))


def try_profile(blob, profile, rec_sizes):
    hv = decode_header(blob, profile["header_key"])
    sizes = [[hv[j]] for j in profile["slots"]]
    lay, nodes = Solver(blob, rec_sizes).solve(sizes, node_budget=20000)
    return lay


def detect_header_key(blob, size0):
    hits = []
    for C in range(256):
        hv = decode_header(blob, C)
        if size0 in hv:
            hits.append((sum(1 for x in hv if x <= blob.n), C))
    hits.sort(reverse=True)
    return [C for _, C in hits]


def generic_search(blob, rec_sizes):
    sl = walk_string_literals(blob, HDR_SIZE)
    if not sl:
        print("[gups] generic: stringLiteral table not found")
        return None
    B0, count, size0, data_size = sl
    size1 = (data_size + 3) & ~3
    print(f"[gups] generic: stringLiteral B={B0} entries={count} size=0x{size0:X} data=0x{size1:X}")
    solver = Solver(blob, rec_sizes)
    for C in detect_header_key(blob, size0)[:4]:
        hv = decode_header(blob, C)
        if size1 not in hv:
            continue
        pool = Counter(hv)
        pool[size0] -= 1
        pool[size1] -= 1
        vals = sorted(set(hv) | {0})
        cands = [[0] if i in ANDROID_EMPTY else vals for i in range(N_SECTIONS)]
        pool[0] += len(ANDROID_EMPTY)
        prefix = [(HDR_SIZE, size0), (HDR_SIZE + size0, size1)]
        lay, nodes = solver.solve(cands, 2, HDR_SIZE + size0 + size1, prefix, pool,
                                  anchors=sorted(hv))
        print(f"[gups] generic: header key 0x{C:02X}, nodes={nodes}, found={lay is not None}")
        if lay:
            return lay
    return None


def section_key(blob, start, size):
    if size < 64:
        return None
    samples = []
    step = max(size // 16, 0x1000)
    for a in range(start, start + size, step):
        samples.append((a, min(0x1000, start + size - a)))
    c = Counter()
    zeros = total = 0
    for a, n in samples:
        blk = blob.d[a:a + n]
        c.update(((x - (a + i)) & 0xFF) for i, x in enumerate(blk))
        zeros += blk.count(0)
        total += n
    B, f = c.most_common(1)[0]
    return B if f > max(0.05 * total, zeros) else None


def brute_string_key(blob, start, size, scorer):
    sample_len = min(size, 0x4000)
    best = (scorer(blob.read(start, sample_len, None)), None)
    for B in range(256):
        s = scorer(blob.read(start, sample_len, B))
        if s > best[0]:
            best = (s, B)
    return best


def xor_ramp(buf, start, B):
    first = (start + B) & 0xFF
    ramp = (bytes(range(first, 256)) + bytes(range(256)) * (len(buf) // 256 + 2))[:len(buf)]
    x = int.from_bytes(buf, "little") ^ int.from_bytes(ramp, "little")
    return x.to_bytes(len(buf), "little")


def decrypt_data(data, version=31, force_generic=False):
    blob = Blob(data)
    rec_sizes = REC_V31
    layout = None
    keys = {}
    if not force_generic:
        layout = try_profile(blob, PROFILE_49, rec_sizes)
        if layout:
            print("[gups] header: known profile validated")
            keys = dict(PROFILE_49["keys"])
    if layout is None:
        print("[gups] header: profile failed -> generic structural search")
        layout = generic_search(blob, rec_sizes)
    if layout is None:
        raise RuntimeError("Could not recover section layout")

    solver = Solver(blob, rec_sizes)
    out = bytearray(data)
    report = []
    for i, (o, s) in enumerate(layout):
        if s == 0:
            report.append({"idx": i, "name": SECTION_NAMES[i], "offset": o, "size": 0, "B": None})
            continue
        B = keys.get(i, "unknown")
        if B != "unknown":
            det = section_key(blob, o, s)
            if det != B and i not in (1, 2):
                B = "unknown"
        if B == "unknown":
            B = section_key(blob, o, s)
        if i == 2:
            sc, B = solver.text_key(o, s)
        elif i == 1:
            scorer = printable_score
            cur = scorer(blob.read(o, min(s, 0x4000), B))
            if cur < 0.80:
                sc, B2 = brute_string_key(blob, o, s, scorer)
                B = B2
        if B is not None:
            out[o:o + s] = xor_ramp(data[o:o + s], o, B)
        report.append({"idx": i, "name": SECTION_NAMES[i], "offset": o, "size": s,
                       "B": None if B is None else B})

    hdr = struct.pack("<II", MAGIC, version) + b"".join(struct.pack("<II", o, s) for o, s in layout)
    out[0:HDR_SIZE] = hdr + b"\0" * (HDR_SIZE - len(hdr))
    return bytes(out), report


def validate_decrypted(data, custom_identifiers=None):
    if len(data) < 8:
        return "File too short"
    magic, ver = struct.unpack_from("<II", data, 0)
    if magic != MAGIC:
        return "Invalid magic"
    so, ss = struct.unpack_from("<II", data, 8 + 2 * 8)
    if so + ss > len(data):
        return "String section out of bounds"
    strs = data[so:so + ss]
    words = [b"MonoBehaviour", b"System"]
    if custom_identifiers:
        words.extend([w.encode("utf-8") if isinstance(w, str) else w for w in custom_identifiers])
    missing = [w.decode("latin-1") for w in words if w + b"\0" not in strs and w not in strs]
    if missing:
        return f"Missing expected identifiers: {', '.join(missing)}"
    if ident_score(strs[:0x10000]) < 0.70:
        return "String section does not look like valid identifiers"
    return None


def run(in_path: str, out_path: str, custom_words=None) -> dict:
    with open(in_path, "rb") as f:
        data = f.read()

    decrypted, report = decrypt_data(data)
    err = validate_decrypted(decrypted, custom_words)
    if err:
        raise RuntimeError(f"Decryption validation failed: {err}")

    with open(out_path, "wb") as f:
        f.write(decrypted)

    return {
        "strategy": "gups",
        "status": "success",
        "size": len(decrypted),
        "sections": report
    }
