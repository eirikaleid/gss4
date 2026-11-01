"""
core/engine_provider.py - Engine Abstraction & Multi-Engine Provider Registry
Defines pluggable adapters for Unity IL2CPP, Unity Mono, Unreal Engine, Godot, and Native ELF.
"""

import abc
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from core.common_ir import CommonIR, ClassIR, FieldIR, MethodIR, NativeSymbolIR


@dataclass
class EngineVerificationPolicy:
    """Configurable verification constraints for Stage 7."""
    engine_name: str = "generic"
    check_rva_alignment: bool = True
    rva_alignment_bytes: int = 4  # ARM64 instruction alignment
    check_typeinfo_alignment: bool = True
    typeinfo_alignment_bytes: int = 8
    max_field_offset: int = 0x10000
    allow_zero_rva: bool = False
    check_method_tokens: bool = False
    token_prefix: Optional[str] = None  # e.g. "0x0600" for .NET MethodDef

    def to_dict(self) -> Dict[str, Any]:
        return {
            "engine_name": self.engine_name,
            "check_rva_alignment": self.check_rva_alignment,
            "rva_alignment_bytes": self.rva_alignment_bytes,
            "check_typeinfo_alignment": self.check_typeinfo_alignment,
            "typeinfo_alignment_bytes": self.typeinfo_alignment_bytes,
            "max_field_offset": self.max_field_offset,
            "allow_zero_rva": self.allow_zero_rva,
            "check_method_tokens": self.check_method_tokens,
            "token_prefix": self.token_prefix,
        }


class BaseEngineProvider(abc.ABC):
    """Abstract interface that each game engine adapter must implement."""

    engine_name: str = "base"
    display_name: str = "Base Engine"

    @abc.abstractmethod
    def get_default_targets(self, arch: str = "arm64-v8a") -> Dict[str, str]:
        """Returns relative paths inside APK to search for in Stage 2."""
        pass

    @abc.abstractmethod
    def get_verification_policy(self) -> EngineVerificationPolicy:
        """Returns the engine-specific verification policy for Stage 7."""
        pass


class UnityIl2CppProvider(BaseEngineProvider):
    """Provider for Unity IL2CPP games."""
    engine_name = "unity_il2cpp"
    display_name = "Unity (IL2CPP AOT Machine Code)"

    def get_default_targets(self, arch: str = "arm64-v8a") -> Dict[str, str]:
        return {
            f"lib/{arch}/libil2cpp.so": "libil2cpp.so",
            "assets/bin/Data/Managed/Metadata/global-metadata.dat": "global-metadata.dat",
            f"lib/{arch}/libunity.so": "libunity.so"
        }

    def get_verification_policy(self) -> EngineVerificationPolicy:
        return EngineVerificationPolicy(
            engine_name="unity_il2cpp",
            check_rva_alignment=True,
            rva_alignment_bytes=4,
            check_typeinfo_alignment=True,
            typeinfo_alignment_bytes=8,
            max_field_offset=0x10000,
            allow_zero_rva=False
        )


class UnityMonoProvider(BaseEngineProvider):
    """Provider for Unity Mono (.NET CLI bytecode) games."""
    engine_name = "unity_mono"
    display_name = "Unity (Mono / .NET Assemblies)"

    def get_default_targets(self, arch: str = "arm64-v8a") -> Dict[str, str]:
        return {
            "assets/bin/Data/Managed/Assembly-CSharp.dll": "Assembly-CSharp.dll",
            "assets/bin/Data/Managed/UnityEngine.dll": "UnityEngine.dll",
            f"lib/{arch}/libmonosgen-2.0.so": "libmonosgen-2.0.so"
        }

    def get_verification_policy(self) -> EngineVerificationPolicy:
        # In Mono, methods use CIL metadata tokens (0x0600xxxx), not machine code RVAs
        return EngineVerificationPolicy(
            engine_name="unity_mono",
            check_rva_alignment=False,  # Tokens do not obey 4-byte machine code alignment
            check_typeinfo_alignment=False,
            max_field_offset=0x10000,
            allow_zero_rva=True,
            check_method_tokens=True,
            token_prefix="0x0600"
        )


class UnrealEngineProvider(BaseEngineProvider):
    """Provider for Unreal Engine 4 / 5 games."""
    engine_name = "unreal"
    display_name = "Unreal Engine 4/5"

    def get_default_targets(self, arch: str = "arm64-v8a") -> Dict[str, str]:
        return {
            f"lib/{arch}/libUE4.so": "libUE4.so",
            f"lib/{arch}/libUnreal.so": "libUnreal.so",
        }

    def get_verification_policy(self) -> EngineVerificationPolicy:
        return EngineVerificationPolicy(
            engine_name="unreal",
            check_rva_alignment=True,
            rva_alignment_bytes=4,
            check_typeinfo_alignment=False,
            max_field_offset=0x20000,
            allow_zero_rva=True
        )


class GenericNativeProvider(BaseEngineProvider):
    """Provider for custom C++ / Cocos2d-x native libraries."""
    engine_name = "native"
    display_name = "Generic Native ELF / Cocos2d-x"

    def get_default_targets(self, arch: str = "arm64-v8a") -> Dict[str, str]:
        return {
            f"lib/{arch}/libcocos2dcpp.so": "libcocos2dcpp.so",
            f"lib/{arch}/libgame.so": "libgame.so",
        }

    def get_verification_policy(self) -> EngineVerificationPolicy:
        return EngineVerificationPolicy(
            engine_name="native",
            check_rva_alignment=True,
            rva_alignment_bytes=4,
            check_typeinfo_alignment=False,
            max_field_offset=0x40000,
            allow_zero_rva=False
        )


# ==============================================================================
# PROVIDER REGISTRY
# ==============================================================================

_PROVIDERS: Dict[str, BaseEngineProvider] = {
    "unity_il2cpp": UnityIl2CppProvider(),
    "il2cpp": UnityIl2CppProvider(),
    "unity_mono": UnityMonoProvider(),
    "mono": UnityMonoProvider(),
    "unreal": UnrealEngineProvider(),
    "ue4": UnrealEngineProvider(),
    "ue5": UnrealEngineProvider(),
    "native": GenericNativeProvider(),
    "generic": GenericNativeProvider(),
}


def get_engine_provider(engine_name: Optional[str] = "unity_il2cpp") -> BaseEngineProvider:
    """Retrieve the registered EngineProvider for the given engine name.
    Defaults to UnityIl2CppProvider if unspecified.
    """
    key = (engine_name or "unity_il2cpp").lower()
    return _PROVIDERS.get(key, _PROVIDERS["unity_il2cpp"])


def list_supported_engines() -> List[Dict[str, str]]:
    """List all supported engine types with their display names."""
    seen = set()
    result = []
    for prov in _PROVIDERS.values():
        if prov.engine_name not in seen:
            seen.add(prov.engine_name)
            result.append({
                "engine": prov.engine_name,
                "display_name": prov.display_name
            })
    return result
