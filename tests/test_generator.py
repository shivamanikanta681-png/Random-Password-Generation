import string
import tempfile
import unittest
from pathlib import Path

from src.generator import (
    PasswordGenerationError,
    calculate_entropy,
    generate_passphrase,
    generate_password,
    rate_entropy,
)


class GeneratorTests(unittest.TestCase):
    def test_password_respects_length(self):
        password = generate_password(length=16)
        self.assertEqual(len(password), 16)

    def test_password_can_exclude_special_characters(self):
        password = generate_password(length=32, use_special=False)
        self.assertFalse(any(character in string.punctuation for character in password))

    def test_password_requires_positive_length(self):
        with self.assertRaises(PasswordGenerationError):
            generate_password(length=0)

    def test_password_length_must_fit_required_groups(self):
        with self.assertRaises(PasswordGenerationError):
            generate_password(
                length=2,
                use_letters=True,
                use_digits=True,
                use_special=True,
            )

    def test_entropy_formula(self):
        self.assertEqual(calculate_entropy(16, 64), 96)

    def test_entropy_rating(self):
        self.assertEqual(rate_entropy(40), "Weak")
        self.assertEqual(rate_entropy(70), "Medium")
        self.assertEqual(rate_entropy(100), "Strong")
        self.assertEqual(rate_entropy(140), "Very Strong")

    def test_passphrase_uses_requested_word_count(self):
        with tempfile.TemporaryDirectory() as directory:
            wordlist = Path(directory) / "words.txt"
            wordlist.write_text("alpha\nbravo\ncharlie\n", encoding="utf-8")

            passphrase = generate_passphrase(
                word_count=5,
                separator=".",
                wordlist_path=wordlist,
            )

        self.assertEqual(len(passphrase.split(".")), 5)


if __name__ == "__main__":
    unittest.main()
