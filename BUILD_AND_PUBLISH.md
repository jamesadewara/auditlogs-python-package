# Build and publish

## Check

```bash
pip install -e ".[dev]"
ruff check src tests && ruff format --check src tests
mypy
pytest
```

## Build

```bash
rm -rf dist
python -m build
python -m twine check dist/*
```

The version lives in `src/auditlogs_verify/_version.py`. Bump it and add a `CHANGELOG.md` entry before
building.

## Smoke-test the wheel

```bash
python -m venv /tmp/al && /tmp/al/bin/pip install dist/auditlogs_verify-*.whl
/tmp/al/bin/auditlogs-verify --version
```

## Publish

Upload with a PyPI API token supplied through the environment or a local `~/.pypirc`. Never
commit a token, and never write one into this repository's files.

```bash
python -m twine upload --repository testpypi dist/*   # rehearse first
python -m twine upload dist/*
```
