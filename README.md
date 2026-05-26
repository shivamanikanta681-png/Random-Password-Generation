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
python main.py --length 16 --no-special
python main.py --length 20 --copy
python main.py --passphrase --words 5 --separator -
python main.py --service github --username student --save
python main.py --list
```

## Web UI

```bash
python web_app.py
```

Then open `http://127.0.0.1:8000`.

## Setup

```bash
pip install -r requirements.txt
python -m unittest discover
```
