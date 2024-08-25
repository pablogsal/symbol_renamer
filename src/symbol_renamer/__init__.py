import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Set, Optional

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

import lief  # type: ignore


logger = logging.getLogger(__name__)


class ELFFileWrapper:
    def __init__(self, filepath: Path):
        self.filepath = filepath
        self._elffile: Optional[ELFFile] = None
        logger.debug("Initialized ELFFileWrapper for %s", filepath)

    def __enter__(self):
        logger.debug("Opening file %s", self.filepath)
        self._file = self.filepath.open("rb")
        self._elffile = ELFFile(self._file)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._file:
            logger.debug("Closing file %s", self.filepath)
            self._file.close()

    @property
    def elffile(self) -> ELFFile:
        if not self._elffile:
            raise ValueError("ELFFile not initialized. Use with statement.")
        return self._elffile


@dataclass
class LibInfo:
    soname: str
    exported_symbols: Set[str]
    imported_symbols: Set[str]
    needed_libs: List[str]

    @staticmethod
    def from_elf_wrapper(lib_wrapper: ELFFileWrapper) -> "LibInfo":
        logger.debug("Creating LibInfo for %s", lib_wrapper.filepath)
        lib_info = LibInfo(
            soname=get_soname(lib_wrapper),
            exported_symbols=get_exported_symbols(lib_wrapper),
            imported_symbols=get_imported_symbols(lib_wrapper),
            needed_libs=get_needed_libraries(lib_wrapper),
        )
        logger.debug("Created LibInfo: %s", lib_info)
        return lib_info


def patch_symbols(filepath: str, symbol_map: dict):
    logger.info(f"Patching {filepath}")
    logger.debug("Symbol map: %s", symbol_map)
    binary = lief.parse(filepath)
    if not binary:
        logger.warning(f"Failed to parse {filepath}")
        return

    patched_count = 0
    for symbol in binary.dynamic_symbols:  # type: ignore
        if symbol.name in symbol_map and not symbol.name.startswith("sympatcher__"):
            logger.debug(
                "Patching symbol: %s -> %s", symbol.name, symbol_map[symbol.name]
            )
            symbol.name = symbol_map[symbol.name]
            patched_count += 1

    logger.info(f"Patched {patched_count} symbols in {filepath}")
    binary.write(filepath)  # type: ignore
    logger.info(f"Wrote patched binary back to {filepath}")


def is_extension_module(elf_wrapper: ELFFileWrapper) -> bool:
    logger.debug("Checking if %s is an extension module", elf_wrapper.filepath)
    elffile = elf_wrapper.elffile

    if elffile.header["e_type"] != "ET_DYN":
        logger.debug("%s is not a shared object", elf_wrapper.filepath)
        return False

    dynamic = elffile.get_section_by_name(".dynamic")
    if dynamic:
        for tag in dynamic.iter_tags():
            if tag.entry.d_tag == "DT_SONAME":
                logger.debug(
                    "%s has a SONAME, not an extension module", elf_wrapper.filepath
                )
                return False

    if ".cpython" not in elf_wrapper.filepath.name:
        logger.debug("%s doesn't have .cpython in its name", elf_wrapper.filepath)
        return False

    symbol_tables = [
        s for s in elffile.iter_sections() if isinstance(s, SymbolTableSection)
    ]
    for section in symbol_tables:
        for symbol in section.iter_symbols():
            if symbol.name and symbol.name.startswith("PyInit_"):
                logger.debug("Found PyInit_ symbol in %s", elf_wrapper.filepath)
                return True

    logger.debug("%s is not an extension module", elf_wrapper.filepath)
    return False


def resolve_origin_path(lib_path: str, base_path: Path) -> Path:
    logger.debug("Resolving $ORIGIN in %s relative to %s", lib_path, base_path)
    if lib_path.startswith("$ORIGIN"):
        resolved_path = base_path.parent / lib_path.replace("$ORIGIN", ".")
        logger.debug("Resolved path: %s", resolved_path)
        return resolved_path
    return Path(lib_path)


def get_vendored_lib_paths(elf_wrapper: ELFFileWrapper) -> List[Path]:
    logger.debug(f"Getting vendored lib paths for {elf_wrapper.filepath}")
    elffile = elf_wrapper.elffile
    dynamic = elffile.get_section_by_name(".dynamic")
    if dynamic:
        for tag in dynamic.iter_tags():
            if tag.entry.d_tag in ["DT_RPATH", "DT_RUNPATH"]:
                paths = tag.rpath.split(":")
                resolved_paths = [
                    resolve_origin_path(p, elf_wrapper.filepath)
                    for p in paths
                    if p.startswith("$ORIGIN")
                ]
                logger.debug(f"Found vendored lib paths: {resolved_paths}")
                return resolved_paths
    logger.debug("No vendored lib paths found")
    return []


def get_exported_symbols(elf_wrapper: ELFFileWrapper) -> Set[str]:
    logger.debug("Getting exported symbols for %s", elf_wrapper.filepath)
    elffile = elf_wrapper.elffile
    symbol_tables = [
        s for s in elffile.iter_sections() if isinstance(s, SymbolTableSection)
    ]
    exported_symbols = set()
    for section in symbol_tables:
        for symbol in section.iter_symbols():
            if (
                symbol["st_info"]["bind"]
                in {"STB_GLOBAL", "STB_WEAK", "STB_GNU_UNIQUE", "STB_LOOS"}
                and symbol["st_shndx"] != "SHN_UNDEF"
            ):
                exported_symbols.add(symbol.name)
            else:
                print(symbol["st_info"]["bind"])
                print(symbol["st_shndx"])
    logger.debug("Found %s exported symbols", len(exported_symbols))
    return exported_symbols


def get_imported_symbols(elf_wrapper: ELFFileWrapper) -> Set[str]:
    logger.debug("Getting imported symbols for %s", elf_wrapper.filepath)
    elffile = elf_wrapper.elffile
    symbol_tables = [
        s for s in elffile.iter_sections() if isinstance(s, SymbolTableSection)
    ]
    imported_symbols = set()
    for section in symbol_tables:
        for symbol in section.iter_symbols():
            if (
                symbol["st_info"]["bind"]
                in {"STB_GLOBAL", "STB_WEAK", "STB_GNU_UNIQUE", "STB_LOOS"}
                and symbol["st_shndx"] == "SHN_UNDEF"
            ):
                imported_symbols.add(symbol.name)
    logger.debug("Found %s imported symbols", len(imported_symbols))
    return imported_symbols


def get_needed_libraries(elf_wrapper: ELFFileWrapper) -> List[str]:
    logger.debug("Getting needed libraries for %s", elf_wrapper.filepath)
    elffile = elf_wrapper.elffile
    dynamic = elffile.get_section_by_name(".dynamic")
    if dynamic:
        needed_libs = [
            tag.needed for tag in dynamic.iter_tags() if tag.entry.d_tag == "DT_NEEDED"
        ]
        logger.debug("Found needed libraries: %s", needed_libs)
        return needed_libs
    logger.debug("No needed libraries found")
    return []


def get_soname(elf_wrapper: ELFFileWrapper) -> str:
    logger.debug("Getting SONAME for %s", elf_wrapper.filepath)
    elffile = elf_wrapper.elffile
    dynamic = elffile.get_section_by_name(".dynamic")
    if dynamic:
        for tag in dynamic.iter_tags():
            if tag.entry.d_tag == "DT_SONAME":
                logger.debug("Found SONAME: %s", tag.soname)
                return tag.soname
    logger.debug("No SONAME found")
    return ""


def create_symbol_map(libs_info: Dict[Path, LibInfo], prefix: str) -> Dict[str, str]:
    logger.debug("Creating symbol map with prefix: %s", prefix)
    symbol_map = {
        symbol: f"{prefix}_{symbol}"
        for lib_info in libs_info.values()
        for symbol in lib_info.exported_symbols
    }
    logger.debug("Created symbol map with %s entries", len(symbol_map))
    return symbol_map


def get_patch_symbols_for_lib(
    lib_info: LibInfo,
    symbol_map: Dict[str, str],
    libs_info: Dict[Path, LibInfo],
    lib_path: Path,
) -> Dict[str, str]:
    logger.debug("Getting patch symbols for lib: %s", lib_path)
    patch_symbols = {}

    for sym, new_sym in symbol_map.items():
        # Case 1: Symbol is exported by this library
        if sym in lib_info.exported_symbols:
            patch_symbols[sym] = new_sym
            logger.debug("Adding exported symbol to patch: %s -> %s", sym, new_sym)
            continue

        # Case 2: Symbol is imported by this library
        if sym in lib_info.imported_symbols:
            # Check if the symbol is exported by any of the needed libraries
            for needed_lib in lib_info.needed_libs:
                needed_lib_path = Path(lib_path) / needed_lib
                if (
                    needed_lib_path in libs_info
                    and sym in libs_info[needed_lib_path].exported_symbols
                ):
                    patch_symbols[sym] = new_sym
                    logger.debug(
                        "Adding imported symbol to patch: %s -> %s", sym, new_sym
                    )
                    break

    logger.debug("Found %s symbols to patch for %s", len(patch_symbols), lib_path)
    return patch_symbols


def process_extension_module(filepath: Path):
    logger.info(f"Processing extension module: {filepath}")
    with ELFFileWrapper(filepath) as extension_wrapper:
        vendored_lib_paths = get_vendored_lib_paths(extension_wrapper)
        logger.debug("Found vendored lib paths: %s", vendored_lib_paths)

        # Process all vendored libraries once
        libs_info: Dict[Path, LibInfo] = {}
        for lib_path in vendored_lib_paths:
            for so_file in lib_path.glob("*.so*"):
                logger.debug("Processing vendored library: %s", so_file)
                with ELFFileWrapper(so_file) as lib_wrapper:
                    libs_info[so_file] = LibInfo.from_elf_wrapper(lib_wrapper)

        vendored_lib_names = "_".join(lib_path.name for lib_path in vendored_lib_paths)
        prefix = f"sympatcher__{vendored_lib_names}"
        logger.info("Using prefix: %s", prefix)

        # Create symbol map
        symbol_map = create_symbol_map(libs_info, prefix)

        # Patch vendored libraries
        for so_file, lib_info in libs_info.items():
            logger.info(f"Patching vendored library: {so_file}")
            patch_symbols_for_lib = get_patch_symbols_for_lib(
                lib_info, symbol_map, libs_info, lib_path
            )
            patch_symbols(str(so_file), patch_symbols_for_lib)

        # Patch the extension module itself
        logger.info(f"Patching extension module: {filepath}")
        extension_symbols = get_exported_symbols(extension_wrapper)
        extension_symbol_map = {
            sym: f"{prefix}_{sym}"
            for sym in extension_symbols
            if not sym.startswith("PyInit_")
        }
        imported_symbols = get_imported_symbols(extension_wrapper)
        for lib_info in libs_info.values():
            for sym in imported_symbols:
                if sym in lib_info.exported_symbols:
                    extension_symbol_map[sym] = f"{prefix}_{sym}"

        logger.debug("Extension symbol map: %s", extension_symbol_map)
        patch_symbols(str(filepath), extension_symbol_map)


def main(target_folder: Path):
    logger.info(f"Starting symbol renaming process for folder: {target_folder}")
    for file in target_folder.rglob("*.so"):
        if file.is_file():
            logger.debug("Checking file: %s", file)
            with ELFFileWrapper(file) as elf_wrapper:
                if is_extension_module(elf_wrapper):
                    logger.info(f"Found extension module: {file}")
                    process_extension_module(file)
    logger.info("Symbol renaming process completed")
