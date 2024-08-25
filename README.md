# Symbol Renamer

[![Build and Test](https://github.com/pablogsal/symbol_renamer/actions/workflows/python-package.yml/badge.svg)](https://github.com/pablogsal/symbol_renamer/actions/workflows/python-package.yml)

## Overview

Symbol Renamer is a tool designed to patch and rename symbols in Python
extension modules and their dependent shared libraries. This tool is
particularly useful for resolving symbol conflicts in complex Python projects
that use multiple shared libraries.

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/symbol-renamer.git
   cd symbol-renamer
   ```

2. Create a virtual environment and activate it:
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
   ```

3. Install the required packages:
   ```
   pip install -r requirements.txt
   ```

## Usage

To use the Symbol Renamer on a Python extension module:

```python
from symbol_renamer import process_extension_module
from pathlib import Path

extension_path = Path("/path/to/your/extension.so")
process_extension_module(extension_path)
```

This will rename the symbols in the extension module and its dependencies, prefixing them with `sympatcher__<extension_name>_`.

## Running Tests

To run the test suite:

```
pytest tests/
```

Contributions are welcome! Please feel free to submit a Pull Request.
