"""
core/common_ir.py - GSS4 Common Intermediate Representation (IR)
Provides a unified, engine-agnostic schema for classes, fields, methods,
and native symbols across Unity IL2CPP, Unity Mono, Unreal Engine, Godot, and Native ELF.
"""

from dataclasses import asdict, dataclass, field
import json
import os
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class FieldIR:
    name: str
    offset: int  # Numerical integer offset (e.g. 0x20)
    type_name: str = "uintptr_t"
    is_static: bool = False
    access: str = "public"
    token: Optional[str] = None  # e.g. "0x04000123" for Mono CLI FieldDef
    comment: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class MethodIR:
    name: str
    rva: Optional[int] = None  # Relative Virtual Address (e.g. 0x51B36B0)
    vtable_index: Optional[int] = None  # For Unreal/C++ virtual tables
    token: Optional[str] = None  # e.g. "0x06000045" for Mono CLI MethodDef
    params_count: int = 0
    return_type: str = "void"
    is_static: bool = False
    is_virtual: bool = False
    comment: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ClassIR:
    name: str
    namespace: str = ""
    type_token: Optional[str] = None
    type_info_va: Optional[int] = None  # VA offset in runtime memory
    type_info_file_offset: Optional[int] = None  # Disk file offset in ELF
    parent_class: Optional[str] = None
    fields: Dict[str, FieldIR] = field(default_factory=dict)
    methods: Dict[str, MethodIR] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        res = {
            "name": self.name,
            "namespace": self.namespace,
            "type_token": self.type_token,
            "type_info_va": hex(self.type_info_va) if self.type_info_va is not None else None,
            "type_info_file_offset": hex(self.type_info_file_offset) if self.type_info_file_offset is not None else None,
            "parent_class": self.parent_class,
            "fields": {k: f.to_dict() for k, f in self.fields.items()},
            "methods": {k: m.to_dict() for k, m in self.methods.items()},
            "metadata": self.metadata
        }
        return res


@dataclass
class NativeSymbolIR:
    name: str
    library: str
    file_offset: Optional[int] = None
    va: Optional[int] = None
    reloc_type: Optional[str] = None
    symbol_type: str = "got_slot"  # "got_slot", "rodata_string", "export", "import"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CommonIR:
    """The master root container for normalized reverse-engineering data."""
    schema_version: str = "2.0"
    engine: str = "unity_il2cpp"  # unity_il2cpp | unity_mono | unreal | godot | native
    arch: str = "arm64-v8a"
    package: Optional[str] = None
    classes: Dict[str, ClassIR] = field(default_factory=dict)
    native_symbols: Dict[str, NativeSymbolIR] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "engine": self.engine,
            "arch": self.arch,
            "package": self.package,
            "classes": {k: c.to_dict() for k, c in self.classes.items()},
            "native_symbols": {k: s.to_dict() for k, s in self.native_symbols.items()},
            "metadata": self.metadata
        }

    def save(self, filepath: str):
        """Serialize CommonIR to JSON file."""
        os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)

    @classmethod
    def load(cls, filepath: str) -> "CommonIR":
        """Load and deserialize CommonIR from JSON file."""
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)

        classes_map = {}
        for cname, cdata in data.get("classes", {}).items():
            fields_map = {}
            for fname, fdata in cdata.get("fields", {}).items():
                off = fdata.get("offset")
                if isinstance(off, str):
                    off = int(off, 0)
                fields_map[fname] = FieldIR(
                    name=fdata.get("name", fname),
                    offset=off,
                    type_name=fdata.get("type_name", "uintptr_t"),
                    is_static=fdata.get("is_static", False),
                    access=fdata.get("access", "public"),
                    token=fdata.get("token"),
                    comment=fdata.get("comment")
                )

            methods_map = {}
            for mname, mdata in cdata.get("methods", {}).items():
                rva = mdata.get("rva")
                if isinstance(rva, str):
                    rva = int(rva, 0)
                methods_map[mname] = MethodIR(
                    name=mdata.get("name", mname),
                    rva=rva,
                    vtable_index=mdata.get("vtable_index"),
                    token=mdata.get("token"),
                    params_count=mdata.get("params_count", 0),
                    return_type=mdata.get("return_type", "void"),
                    is_static=mdata.get("is_static", False),
                    is_virtual=mdata.get("is_virtual", False),
                    comment=mdata.get("comment")
                )

            va = cdata.get("type_info_va")
            if isinstance(va, str):
                va = int(va, 0)
            fo = cdata.get("type_info_file_offset")
            if isinstance(fo, str):
                fo = int(fo, 0)

            classes_map[cname] = ClassIR(
                name=cdata.get("name", cname),
                namespace=cdata.get("namespace", ""),
                type_token=cdata.get("type_token"),
                type_info_va=va,
                type_info_file_offset=fo,
                parent_class=cdata.get("parent_class"),
                fields=fields_map,
                methods=methods_map,
                metadata=cdata.get("metadata", {})
            )

        native_map = {}
        for sname, sdata in data.get("native_symbols", {}).items():
            fo = sdata.get("file_offset")
            if isinstance(fo, str):
                fo = int(fo, 0)
            va = sdata.get("va")
            if isinstance(va, str):
                va = int(va, 0)
            native_map[sname] = NativeSymbolIR(
                name=sdata.get("name", sname),
                library=sdata.get("library", ""),
                file_offset=fo,
                va=va,
                reloc_type=sdata.get("reloc_type"),
                symbol_type=sdata.get("symbol_type", "got_slot")
            )

        return cls(
            schema_version=data.get("schema_version", "2.0"),
            engine=data.get("engine", "unity_il2cpp"),
            arch=data.get("arch", "arm64-v8a"),
            package=data.get("package"),
            classes=classes_map,
            native_symbols=native_map,
            metadata=data.get("metadata", {})
        )

    def to_legacy_data_dict(self) -> Dict[str, Any]:
        """Convert CommonIR to the legacy dictionary structure expected by Stage 6 code generators.
        Ensures 100% backward compatibility with cpp_gen.py, rust_gen.py, csharp_gen.py.
        """
        methods_dict = {}
        fields_dict = {}
        typeinfos_dict = {}
        native_dict = {}

        for cname, cdata in self.classes.items():
            fields_dict[cname] = {}
            for fname, fdata in cdata.fields.items():
                fields_dict[cname][fname] = fdata.offset

            for mname, mdata in cdata.methods.items():
                if mdata.rva is not None:
                    methods_dict[f"{cname}_{mname}"] = mdata.rva

            if cdata.type_info_file_offset is not None:
                typeinfos_dict[cname] = cdata.type_info_file_offset
            elif cdata.type_info_va is not None:
                typeinfos_dict[cname] = cdata.type_info_va

        for sname, sdata in self.native_symbols.items():
            off = sdata.file_offset if sdata.file_offset is not None else (sdata.va or 0)
            native_dict[sname] = off

        return {
            "methods": methods_dict,
            "fields": fields_dict,
            "typeinfos": typeinfos_dict,
            "native": native_dict,
            "engine": self.engine,
            "arch": self.arch
        }
