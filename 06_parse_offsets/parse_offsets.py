#!/usr/bin/env python3
"""
06_parse_offsets/parse_offsets.py - Generalized Profile-Driven Offset Parser
Extracts method RVAs, field offsets, TypeInfo pointers, and native offsets from
Il2CppDumper output and generates clean C++ headers and structured JSON.

Usage:
    python parse_offsets.py --dump dump.cs --script script.json --so libil2cpp.so \
        --profile ../profiles/royale.json --out ./offsets.h [--native-json native.json]
"""

import argparse
import json
import os
import re
import struct
import sys
from collections import OrderedDict
from datetime import datetime

MAX_FIELD_OFF = 0x10000

CLASS_RE = re.compile(r"^(?:(?:public|private|internal|protected|static|sealed|abstract|readonly|ref|unsafe)\s+)*"
                      r"(class|struct|enum|interface)\s+(.+?)(?:\s+:\s+(.*?))?\s*//\s*TypeDefIndex:\s*(\d+)\s*$")
V1_CLASS_RE = re.compile(r"^\s*(?:public|private|internal|protected)?\s*(?:sealed\s+)?(?:abstract\s+)?class\s+([A-Za-z0-9_]+)")
RVA_RE = re.compile(r"//\s*RVA:\s*(0x[0-9A-Fa-f]+)\s+Offset:\s*(0x[0-9A-Fa-f]+)")
METHOD_RE = re.compile(r"(?:public|private|internal|protected|static|virtual|override)\s+[\w<>,\[\]\s\.\?]+?\s+"
                       r"([A-Za-z0-9_]+)\s*\((.*?)\)")
FIELD_MODS = r"(?:public|private|internal|protected|static|readonly|const|volatile|new|fixed|unsafe)"
FIELD_RE = re.compile(r"^\t((?:" + FIELD_MODS + r"\s+)+)(.+?)\s+([^\s;=]+?)\s*(?:=\s*[^;]*)?;\s*"
                      r"(?://\s*(0x[0-9A-Fa-f]+))?\s*$")
BACKING_RE = re.compile(r"^<([A-Za-z0-9_]+)>k__BackingField$")


def count_params(param_str):
    param_str = param_str.strip()
    if not param_str:
        return 0
    param_str = re.sub(r"<[^>]*>", "", param_str)
    return len([p for p in param_str.split(",") if p.strip()])


def field_to_const(fname):
    s = fname.lstrip("_")
    if not s:
        return "UNKNOWN"
    if re.match(r"^[A-Z0-9_]+$", s):
        return s
    s = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", s)
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s)
    s = re.sub(r"[^A-Za-z0-9]+", "_", s)
    s = re.sub(r"_+", "_", s).strip("_")
    return s.upper()


def sanitize(name):
    return re.sub(r"[^A-Za-z0-9_]", "_", name)


def split_top(name):
    depth = 0
    for i, ch in enumerate(name):
        if ch == "<":
            depth += 1
        elif ch == ">":
            depth -= 1
        elif ch == "." and depth == 0:
            return name[:i]
    return name


def strip_generic(name):
    return re.sub(r"<.*$", "", name).strip()


class Klass:
    __slots__ = ("idx", "ns", "kind", "name", "top", "nested", "bases", "fields", "methods", "skipped",
                 "v1_owner", "allfields")

    def __init__(self, idx, ns, kind, name, bases):
        self.idx, self.ns, self.kind, self.name = idx, ns, kind, name
        self.top = split_top(name)
        self.nested = self.top != name
        self.bases = bases
        self.fields = []
        self.methods = []
        self.skipped = 0
        self.allfields = []
        self.v1_owner = None

    @property
    def qual(self):
        return f"{self.ns}.{self.name}" if self.ns else self.name

    def base_class(self):
        if not self.bases:
            return None
        first = self.bases.split(",")[0].strip()
        return strip_generic(first) or None


def parse_dump(path):
    classes = []
    ns = ""
    cur = None
    section = None
    pend = None
    bad_fields = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.startswith("// Namespace:"):
                ns = line[13:].strip()
                continue
            if not line.startswith("\t") and "TypeDefIndex" in line:
                m = CLASS_RE.match(line)
                if not m:
                    raise ValueError(f"Unparsed type header: {line.strip()[:160]}")
                prev_owner = classes[-1].v1_owner if classes else None
                cur = Klass(len(classes), ns, m.group(1), m.group(2).strip(), m.group(3))
                v1m = V1_CLASS_RE.match(line)
                cur.v1_owner = v1m.group(1) if v1m else prev_owner
                classes.append(cur)
                section, pend = None, None
                continue
            if cur is None:
                continue
            s = line.strip()
            if s.startswith("// Fields"):
                section = "f"
                continue
            if s.startswith("// Properties"):
                section = "p"
                continue
            if s.startswith("// Methods"):
                section = "m"
                continue
            if section == "f":
                fm = FIELD_RE.match(line)
                if fm:
                    mods = fm.group(1).split()
                    if fm.group(4) is not None:
                        cur.allfields.append((fm.group(3), int(fm.group(4), 16), "static" in mods))
                    if cur.kind != "class":
                        continue
                    if "static" in mods or "const" in mods:
                        cur.skipped += 1
                        continue
                    if fm.group(4) is None:
                        continue
                    off = int(fm.group(4), 16)
                    if off >= MAX_FIELD_OFF:
                        bad_fields.append(f"{cur.qual}::{fm.group(3)}=0x{off:X}")
                        continue
                    cur.fields.append((fm.group(3), fm.group(2).strip(), off))
                continue
            if section == "m":
                rm = RVA_RE.search(line)
                if rm:
                    pend = (int(rm.group(1), 16), int(rm.group(2), 16))
                    continue
                if pend:
                    mm = METHOD_RE.search(line)
                    if mm:
                        cur.methods.append((mm.group(1), count_params(mm.group(2)), pend[0], pend[1]))
                        pend = None
    return classes, bad_fields


class Model:
    def __init__(self, classes, preferred_ns=""):
        self.classes = classes
        self.preferred_ns = preferred_ns
        self.by_top = {}
        self.by_name = {}
        self.by_v1 = {}
        for k in classes:
            if k.v1_owner:
                self.by_v1.setdefault(k.v1_owner, []).append(k)
            self.by_top.setdefault(k.top, []).append(k)
            self.by_name.setdefault(k.name, []).append(k)

    def pick(self, name, kinds=("class", "struct")):
        ns_hint = None
        if "." in name and not name.startswith("<"):
            ns_hint, name = name.rsplit(".", 1)
        cands = [k for k in self.by_name.get(name, []) if k.kind in kinds]
        if ns_hint:
            cands = [k for k in cands if k.ns.endswith(ns_hint)]
        if not cands:
            return None
        if self.preferred_ns:
            pref = [k for k in cands if k.ns == self.preferred_ns or k.ns.startswith(self.preferred_ns + ".")]
            if pref:
                return pref[0]
        return cands[0]


def load_segments(so_path):
    with open(so_path, "rb") as f:
        data = f.read(0x40)
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        raise ValueError(f"{so_path}: not ELF64")
    phoff = struct.unpack_from("<Q", data, 0x20)[0]
    phentsize, phnum = struct.unpack_from("<HH", data, 0x36)
    with open(so_path, "rb") as f:
        f.seek(phoff)
        ph = f.read(phentsize * phnum)
    segs = []
    for i in range(phnum):
        p_type, p_flags, off, va, _pa, fsz, _msz, _al = struct.unpack_from("<IIQQQQQQ", ph, i * phentsize)
        if p_type == 1:
            segs.append((off, va, fsz, p_flags))
    return segs


def va_to_off(va, segs):
    for off, seg_va, fsz, _fl in segs:
        if seg_va <= va < seg_va + fsz:
            return va - seg_va + off
    return None


def scan_typeinfo(script_path):
    addr_re = re.compile(r'"Address":\s*(\d+)')
    name_re = re.compile(r'"Name":\s*"([^"]+_TypeInfo)"')
    out = {}
    last = None
    with open(script_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if '"Address"' in line:
                m = addr_re.search(line)
                last = int(m.group(1)) if m else None
                continue
            if "_TypeInfo" in line and last is not None:
                m = name_re.search(line)
                if m:
                    out.setdefault(m.group(1), last)
                last = None
    return out


def resolve_typeinfo(script_json_path, so_path, profile):
    segs = load_segments(so_path)
    type_info_map = scan_typeinfo(script_json_path)

    resolved = {}
    auto_re = re.compile(profile.get("typeinfo_auto_pattern", r"^.*Manager_TypeInfo$"))

    # Required TypeInfos
    for req in profile.get("typeinfo_required", []):
        key = f"{profile.get('preferred_namespace', '')}.{req}_TypeInfo".strip(".")
        va = type_info_map.get(key) or type_info_map.get(f"{req}_TypeInfo")
        if va is not None:
            foff = va_to_off(va, segs)
            if foff is not None:
                resolved[req] = foff
            else:
                print(f"[WARN] TypeInfo VA for {req} outside PT_LOAD")
        else:
            print(f"[WARN] Required TypeInfo not found: {req}")

    # Extra TypeInfos
    for ext in profile.get("typeinfo_extra", []):
        key = f"{profile.get('preferred_namespace', '')}.{ext}_TypeInfo".strip(".")
        va = type_info_map.get(key) or type_info_map.get(f"{ext}_TypeInfo")
        if va is not None:
            foff = va_to_off(va, segs)
            if foff is not None:
                resolved[ext] = foff

    # Auto pattern matches
    for name, va in type_info_map.items():
        m = auto_re.match(name)
        if m:
            short = m.group(1) if m.groups() else name
            if short not in resolved:
                foff = va_to_off(va, segs)
                if foff is not None:
                    resolved[short] = foff

    return resolved


def generate_header(profile, model, typeinfo_map, native_offsets, out_header_path, out_json_path=None):
    ns_name = profile.get("header_namespace", "Offsets")
    priority_classes = profile.get("priority_classes", {})
    field_classes = profile.get("field_classes", [])
    keywords = [kw.lower() for kw in profile.get("keywords", [])]
    method_cap = profile.get("method_cap", 200)

    # 1. Methods
    methods = OrderedDict()
    # Priority methods
    for cname, meth_spec in priority_classes.items():
        k = model.pick(cname)
        if not k:
            continue
        for mname, expected_params in meth_spec.items():
            for m_item in k.methods:
                if m_item[0] == mname and (expected_params == -1 or m_item[1] == expected_params):
                    symbol = f"{cname}_{mname}"
                    if symbol not in methods:
                        methods[symbol] = m_item[3]  # Method offset
                    break

    # Keyword methods
    budget = method_cap - len(methods)
    for k in model.classes:
        if budget <= 0:
            break
        if k.kind != "class" or k.top in priority_classes or "<" in k.name:
            continue
        cls_hit = any(kw in k.top.lower() for kw in keywords)
        for m_item in k.methods:
            if budget <= 0:
                break
            if not (cls_hit or any(kw in m_item[0].lower() for kw in keywords)):
                continue
            symbol = f"{k.name}_{m_item[0]}"
            if symbol not in methods:
                methods[symbol] = m_item[3]
                budget -= 1

    # 2. Fields
    fields = OrderedDict()
    for cname in field_classes:
        k = model.pick(cname)
        if not k:
            continue
        fields[cname] = OrderedDict()
        for f_name, f_type, f_off in k.fields:
            bm = BACKING_RE.match(f_name)
            clean_name = bm.group(1) if bm else f_name
            const_name = field_to_const(clean_name)
            if const_name in fields[cname]:
                const_name = f"{const_name}_{f_off:X}"
            fields[cname][const_name] = f_off

    # 3. TypeInfos
    typeinfos = OrderedDict(sorted(typeinfo_map.items()))

    # Build Header
    lines = [
        "// ===========================================================================",
        f"// Generated by GSS4 Offset Pipeline - Profile: {profile.get('name', 'generic')}",
        f"// Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "// ===========================================================================",
        "#pragma once",
        "#include <cstdint>",
        "",
        f"namespace {ns_name} {{",
        "",
        "    // ========================================================================",
        "    // METHOD RVAs (libil2cpp.so)",
        "    // ========================================================================"
    ]

    for sym, rva in methods.items():
        lines.append(f"    constexpr uintptr_t {sanitize(sym)} = 0x{rva:X};")

    lines.append("")
    lines.append("    // ========================================================================")
    lines.append("    // CLASS FIELD OFFSETS")
    lines.append("    // ========================================================================")

    for cname, cfields in fields.items():
        if not cfields:
            continue
        lines.append(f"    namespace {sanitize(cname)} {{")
        for fname, foff in cfields.items():
            lines.append(f"        constexpr uintptr_t {sanitize(fname)} = 0x{foff:X};")
        lines.append("    }")

    lines.append("")
    lines.append("    // ========================================================================")
    lines.append("    // TYPEINFO POINTERS (libil2cpp.so file offsets)")
    lines.append("    // ========================================================================")
    lines.append("    namespace TypeInfo {")
    for tname, foff in typeinfos.items():
        const_name = field_to_const(tname)
        lines.append(f"        constexpr uintptr_t {const_name} = 0x{foff:X};")
    lines.append("    }")

    if native_offsets:
        lines.append("")
        lines.append("    // ========================================================================")
        lines.append("    // NATIVE OFFSETS (libunity.so / native libraries)")
        lines.append("    // ========================================================================")
        lines.append("    namespace Native {")
        for nname, foff in native_offsets.items():
            lines.append(f"        constexpr uintptr_t {sanitize(nname)} = 0x{foff:X};")
        lines.append("    }")

    lines.append(f"}} // namespace {ns_name}")
    lines.append("")

    header_text = "\n".join(lines)
    os.makedirs(os.path.dirname(os.path.abspath(out_header_path)), exist_ok=True)
    with open(out_header_path, "w", encoding="utf-8") as f:
        f.write(header_text)

    structured_data = {
        "profile": profile.get("name"),
        "timestamp": datetime.now().isoformat(),
        "methods": methods,
        "fields": fields,
        "typeinfos": typeinfos,
        "native": native_offsets
    }
    if out_json_path:
        os.makedirs(os.path.dirname(os.path.abspath(out_json_path)), exist_ok=True)
        with open(out_json_path, "w", encoding="utf-8") as jf:
            json.dump(structured_data, jf, indent=2)

    return structured_data


def main():
    parser = argparse.ArgumentParser(description="Parse Il2CppDumper dump files and emit offsets.h.")
    parser.add_argument("--dump", required=True, help="Path to dump.cs")
    parser.add_argument("--script", required=True, help="Path to script.json")
    parser.add_argument("--so", required=True, help="Path to libil2cpp.so")
    parser.add_argument("--profile", required=True, help="Path to application profile JSON")
    parser.add_argument("--out", required=True, help="Destination C++ header path")
    parser.add_argument("--out-json", help="Destination structured JSON path")
    parser.add_argument("--native-json", help="Path to native.json (optional)")
    parser.add_argument("--report", help="Path to output parse report JSON")

    args = parser.parse_args()

    with open(args.profile, "r", encoding="utf-8") as pf:
        profile = json.load(pf)

    print(f"[*] Parsing dump.cs: {args.dump} ...")
    classes, bad_fields = parse_dump(args.dump)
    print(f"[OK] Parsed {len(classes)} classes from dump.cs.")

    model = Model(classes, preferred_ns=profile.get("preferred_namespace", "GameMain"))

    print(f"[*] Resolving TypeInfos from script.json: {args.script} ...")
    typeinfos = resolve_typeinfo(args.script, args.so, profile)
    print(f"[OK] Resolved {len(typeinfos)} TypeInfo offsets.")

    native_offsets = {}
    if args.native_json and os.path.exists(args.native_json):
        with open(args.native_json, "r", encoding="utf-8") as nf:
            native_offsets = json.load(nf)

    print(f"[*] Generating header: {args.out} ...")
    data = generate_header(profile, model, typeinfos, native_offsets, args.out, args.out_json)
    print(f"[OK] Header generated successfully: {args.out} ({len(data['methods'])} methods, {sum(len(f) for f in data['fields'].values())} fields)")

    if args.report:
        report = {
            "classes_count": len(classes),
            "methods_count": len(data["methods"]),
            "fields_count": sum(len(f) for f in data["fields"].values()),
            "typeinfos_count": len(data["typeinfos"]),
            "native_count": len(data["native"])
        }
        with open(args.report, "w", encoding="utf-8") as rf:
            json.dump(report, rf, indent=2)


if __name__ == "__main__":
    main()
