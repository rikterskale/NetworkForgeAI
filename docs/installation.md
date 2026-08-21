# Installation

## Supported runtime

Use Python 3.10 or newer. The recommended setup is an isolated virtual environment:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip setuptools wheel
.venv/bin/python -m pip install -e '.[dev,runtime]'
```

If the host does not provide `pip` or `venv`, install the operating-system packages
`python3-pip` and `python3-venv`, or use the repository Dockerfile.

## Verify installation

```bash
.venv/bin/python -m networkforgeai.cli --help
.venv/bin/python tools/user_readiness.py
```

Live scanning requires an explicitly configured sandbox image and authorized target
scope. Never place real credentials in `.env.example` or source control.

