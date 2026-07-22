from pathlib import Path

from elftools.elf.elffile import ELFFile

from .protections import Protections, Relro

_PF_X = 0x1
_DF_BIND_NOW = 0x8
_DF_1_NOW = 0x1


def analyze_protections(binary_path: str | Path) -> Protections:
    with open(binary_path, "rb") as f:
        elffile = ELFFile(f)
        return Protections(
            nx=_detect_nx(elffile),
            pie=elffile.header["e_type"] == "ET_DYN",
            canary=_has_symbol(elffile, "__stack_chk_fail"),
            relro=_detect_relro(elffile),
        )


def _detect_nx(elffile: ELFFile) -> bool:
    for segment in elffile.iter_segments():
        if segment["p_type"] == "PT_GNU_STACK":
            return not bool(segment["p_flags"] & _PF_X)
    # No GNU_STACK segment at all: pre-NX-aware toolchains default to an
    # executable stack.
    return False


def _detect_relro(elffile: ELFFile) -> Relro:
    has_relro_segment = any(
        segment["p_type"] == "PT_GNU_RELRO" for segment in elffile.iter_segments()
    )
    if not has_relro_segment:
        return Relro.NONE

    dynamic = elffile.get_section_by_name(".dynamic")
    if dynamic is not None and _has_bind_now(dynamic):
        return Relro.FULL
    return Relro.PARTIAL


def _has_bind_now(dynamic_section) -> bool:
    for tag in dynamic_section.iter_tags():
        if tag.entry.d_tag == "DT_BIND_NOW":
            return True
        if tag.entry.d_tag == "DT_FLAGS" and tag.entry.d_val & _DF_BIND_NOW:
            return True
        if tag.entry.d_tag == "DT_FLAGS_1" and tag.entry.d_val & _DF_1_NOW:
            return True
    return False


def _has_symbol(elffile: ELFFile, name: str) -> bool:
    for section_name in (".dynsym", ".symtab"):
        section = elffile.get_section_by_name(section_name)
        if section is None:
            continue
        if any(sym.name == name for sym in section.iter_symbols()):
            return True
    return False
