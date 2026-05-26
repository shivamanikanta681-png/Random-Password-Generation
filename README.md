# Secure Password Generator

A production-style Python password generator with:

- Secure randomness from `secrets`
- `argparse` command-line flags
- Password entropy scoring
- Diceware-style passphrase generation
- Optional clipboard copying with `pyperclip`
- Optional encrypted SQLite storage using `cryptography`
- Unit tests with Python's built-in `unittest`

## Examples

```bash
python -m src.cli --length 16 --no-special
python -m src.cli --length 20 --copy
python -m src.cli --passphrase --words 5 --separator -
python -m src.cli --service github --username student --save
python -m src.cli --list
```

## Web UI

```bash
python main.py
```

Then open `http://127.0.0.1:8000`.

## Setup

```bash
pip install -r requirements.txt
python -m unittest discover
```
