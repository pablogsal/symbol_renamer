import subprocess
import sys
from pathlib import Path
import pytest
import os
from elftools.elf.elffile import ELFFile

from symbol_renamer import process_extension_module


def compile_shared_lib(source_file: Path, output_file: Path, extra_flags=None):
    cmd = ["gcc", "-shared", "-fPIC", "-o", str(output_file), str(source_file)]
    if extra_flags:
        cmd.extend(extra_flags)
    subprocess.run(cmd, check=True)


def create_extension_module(path: Path, name: str, libs):
    setup_py = path / "setup.py"
    module_c = path / f"{name}.c"

    with open(setup_py, "w") as f:
        f.write(
            f"""
from setuptools import setup, Extension

module = Extension('{name}',
                   sources=['{name}.c'],
                   libraries={libs},
                   library_dirs=['.'])

setup(name='{name}',
      version='1.0',
      ext_modules=[module])
"""
        )

    with open(module_c, "w") as f:
        f.write(
            f"""
#include <Python.h>

void lib1_func();
void lib2_func();

static PyObject* test_func(PyObject* self, PyObject* args) {{
    lib1_func();
    lib2_func();
    return PyUnicode_FromString("Extension test successful!");
}}

static PyMethodDef Methods[] = {{
    {{"test", test_func, METH_NOARGS, "Test function"}},
    {{NULL, NULL, 0, NULL}}
}};

static struct PyModuleDef module = {{
    PyModuleDef_HEAD_INIT,
    "{name}",
    NULL,
    -1,
    Methods
}};

PyMODINIT_FUNC PyInit_{name}(void) {{
    return PyModule_Create(&module);
}}
"""
        )


def get_symbols(file_path: Path):
    with open(file_path, "rb") as f:
        elffile = ELFFile(f)
        symtab = elffile.get_section_by_name(".dynsym")
        if symtab:
            return {sym.name for sym in symtab.iter_symbols() if sym.name}
    return set()


@pytest.fixture(scope="module")
def test_env(tmp_path_factory):
    test_dir = tmp_path_factory.mktemp("test_libs_and_extension")

    # Create lib3 (no dependencies)
    lib3_source = test_dir / "lib3.c"
    lib3_source.write_text(
        """
    #include <stdio.h>
    void lib3_func() {
        printf("lib3_func called\\n");
    }
    """
    )
    compile_shared_lib(lib3_source, test_dir / "lib3.so")

    # Create lib2 (no dependencies)
    lib2_source = test_dir / "lib2.c"
    lib2_source.write_text(
        """
    #include <stdio.h>
    void lib2_func() {
        printf("lib2_func called\\n");
    }
    """
    )
    compile_shared_lib(lib2_source, test_dir / "lib2.so")

    # Create lib1 (depends on lib2)
    lib1_source = test_dir / "lib1.c"
    lib1_source.write_text(
        """
    #include <stdio.h>
    void lib2_func();
    void lib1_func() {
        printf("lib1_func called\\n");
        lib2_func();
    }
    """
    )
    compile_shared_lib(lib1_source, test_dir / "lib1.so", ["-L", str(test_dir), "-l2"])

    # Create extension module
    create_extension_module(test_dir, "test_extension", "['1', '2']")

    # Build wheel
    subprocess.run(
        [sys.executable, "setup.py", "bdist_wheel"], cwd=test_dir, check=True
    )

    return test_dir


def test_extension_patching(test_env):
    # Find the wheel file
    wheel_file = list(test_env.glob("dist/*.whl"))[0]

    # Run auditwheel
    subprocess.run(
        [
            sys.executable,
            "-m",
            "auditwheel",
            "repair",
            str(wheel_file),
            "-w",
            str(test_env),
        ],
        check=True,
        env={**os.environ, "LD_LIBRARY_PATH": str(test_env)},
    )

    # Find the repaired wheel created by auditwheel
    repaired_wheel = list(test_env.glob("test_extension-1.0-*manylinux*.whl"))[0]

    # Extract the repaired wheel
    extract_dir = test_env / "extracted_wheel"
    extract_dir.mkdir(exist_ok=True)
    subprocess.run(["unzip", str(repaired_wheel), "-d", str(extract_dir)], check=True)

    # Find the extension file in the extracted wheel
    extension_file = list(extract_dir.glob("**/*.so"))[0]

    # Run our patcher
    process_extension_module(extension_file)

    # Define expected patched symbols for each library

    expected_patched_symbols = {
        "lib1": {
            "sympatcher__test_extension.libs_lib1_func",
            "sympatcher__test_extension.libs_lib2_func",
        },
        "lib2": {"sympatcher__test_extension.libs_lib2_func"},
        "lib3": {"sympatcher__test_extension.libs_lib3_func"},
        extension_file.stem: {
            "sympatcher__test_extension.libs_lib1_func",
            "sympatcher__test_extension.libs_lib2_func",
        },
    }

    # Verify that symbols were changed in the extension and libs
    for file in [extension_file] + list(extract_dir.glob("**/*.so")):
        symbols = get_symbols(file)
        canonical_name = next(
            (name for name in expected_patched_symbols if file.name.startswith(name)),
            None,
        )
        expected_symbols = expected_patched_symbols.get(canonical_name, set())
        missing_symbols = expected_symbols - symbols
        unexpected_symbols = {
            sym for sym in symbols if sym.startswith("sympatcher__")
        } - expected_symbols

        assert (
            not missing_symbols
        ), f"Missing expected patched symbols in {file}: {missing_symbols}"
        assert (
            not unexpected_symbols
        ), f"Unexpected patched symbols in {file}: {unexpected_symbols}"

        print(f"Verified symbols in {file}")

    # Test the patched extension in a separate process
    test_script = extract_dir / "test_script.py"
    test_script.write_text(
        """
import sys
import test_extension

result = test_extension.test()
print(result)
sys.exit(0 if result == "Extension test successful!" else 1)
"""
    )

    result = subprocess.run(
        [sys.executable, str(test_script)],
        cwd=extract_dir,
        capture_output=True,
        text=True,
    )

    assert (
        result.returncode == 0
    ), f"Extension test failed: {result.stdout} {result.stderr}"
    assert "Extension test successful!" in result.stdout
