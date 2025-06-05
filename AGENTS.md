# Guidelines for Contributors

This project contains tooling to emulate devices and interact with Microsoft Intune. When submitting changes, please follow these guidelines so that reviews and testing remain consistent.

## Directory overview
- `pytune.py` – main command line interface
- `device/` – platform specific implementations
- `utils/` – helper functions and the logging module
- `requirements.txt` – python dependencies

## Development style
- Target Python 3.10 or newer.
- Keep lines shorter than 120 characters.
- Prefer using the provided `Logger` class over raw `print` calls.
- Ensure new modules include docstrings describing their purpose.
- Run `black .` before committing to keep formatting consistent (you may need to install `black`).

## Pre‑commit checks
Run the following command to ensure files compile before committing:
```bash
python3 -m py_compile pytune.py device/*.py utils/*.py
```
Remove any `__pycache__` directories after running the check.

## Pull requests
Include a short summary of your changes and the test commands you executed in the PR description.

