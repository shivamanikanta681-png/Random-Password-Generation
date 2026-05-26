import math
import secrets
import string
from pathlib import Path


DEFAULT_WORDLIST = Path(__file__).with_name("wordlist.txt")


class PasswordGenerationError(ValueError):
    """Raised when password generation options are invalid."""


def get_character_pool(use_letters=True, use_digits=True, use_special=True):
    pool = ""
    required_sets = []

    if use_letters:
        pool += string.ascii_letters
        required_sets.append(string.ascii_letters)
    if use_digits:
        pool += string.digits
        required_sets.append(string.digits)
    if use_special:
        pool += string.punctuation
        required_sets.append(string.punctuation)

    if not pool:
        raise PasswordGenerationError("Enable at least one character group.")

    return pool, required_sets


def calculate_entropy(length, pool_size):
    if length <= 0 or pool_size <= 0:
        return 0.0
    return length * math.log2(pool_size)


def rate_entropy(bits):
    if bits < 50:
        return "Weak"
    if bits < 80:
        return "Medium"
    if bits < 120:
        return "Strong"
    return "Very Strong"


def generate_password(length=12, use_letters=True, use_digits=True, use_special=True):
    pool, required_sets = get_character_pool(use_letters, use_digits, use_special)

    if length <= 0:
        raise PasswordGenerationError("Password length must be greater than zero.")
    if length < len(required_sets):
        raise PasswordGenerationError(
            f"Length must be at least {len(required_sets)} for the selected character groups."
        )

    password = [secrets.choice(characters) for characters in required_sets]
    password.extend(secrets.choice(pool) for _ in range(length - len(password)))
    secrets.SystemRandom().shuffle(password)

    return "".join(password)


def load_words(wordlist_path=DEFAULT_WORDLIST):
    path = Path(wordlist_path)
    words = [
        word.strip().lower()
        for word in path.read_text(encoding="utf-8").splitlines()
        if word.strip() and not word.startswith("#")
    ]
    if not words:
        raise PasswordGenerationError("Wordlist is empty.")
    return words


def generate_passphrase(word_count=4, separator="-", wordlist_path=DEFAULT_WORDLIST):
    if word_count <= 0:
        raise PasswordGenerationError("Word count must be greater than zero.")

    words = load_words(wordlist_path)
    selected = [secrets.choice(words) for _ in range(word_count)]
    return separator.join(selected)
