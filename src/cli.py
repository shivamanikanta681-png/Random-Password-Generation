import argparse
import sys

from .database import PasswordManager
from .encryptor import EncryptionUnavailableError
from .generator import (
    PasswordGenerationError,
    calculate_entropy,
    generate_passphrase,
    generate_password,
    get_character_pool,
    load_words,
    rate_entropy,
)


def copy_to_clipboard(value):
    try:
        import pyperclip
    except ImportError:
        return False, "pyperclip is not installed. Run: pip install -r requirements.txt"

    pyperclip.copy(value)
    return True, "Copied to clipboard."


def build_parser():
    parser = argparse.ArgumentParser(
        description="Generate secure passwords and passphrases."
    )
    parser.add_argument("--length", type=int, default=12, help="Password length.")
    parser.add_argument("--no-letters", action="store_true", help="Exclude letters.")
    parser.add_argument("--no-digits", action="store_true", help="Exclude digits.")
    parser.add_argument("--no-special", action="store_true", help="Exclude symbols.")
    parser.add_argument("--passphrase", action="store_true", help="Generate words instead.")
    parser.add_argument("--words", type=int, default=4, help="Number of passphrase words.")
    parser.add_argument("--separator", default="-", help="Passphrase word separator.")
    parser.add_argument("--copy", action="store_true", help="Copy result to clipboard.")
    parser.add_argument("--save", action="store_true", help="Save result in encrypted SQLite storage.")
    parser.add_argument("--service", help="Service name for saved password.")
    parser.add_argument("--username", default="", help="Username for saved password.")
    parser.add_argument("--database", default="passwords.db", help="SQLite database path.")
    parser.add_argument("--key-file", default="secret.key", help="Fernet key file path.")
    parser.add_argument("--list", action="store_true", help="List saved records.")
    parser.add_argument("--reveal", action="store_true", help="Reveal passwords when listing.")
    return parser


def describe_entropy(args, generated_value):
    if args.passphrase:
        pool_size = len(load_words())
        bits = calculate_entropy(args.words, pool_size)
    else:
        pool, _ = get_character_pool(
            not args.no_letters,
            not args.no_digits,
            not args.no_special,
        )
        bits = calculate_entropy(len(generated_value), len(pool))

    return bits, rate_entropy(bits)


def handle_list(args):
    manager = PasswordManager(args.database, args.key_file)
    records = manager.list_passwords(reveal=args.reveal)
    if not records:
        print("No saved passwords yet.")
        return 0

    for record in records:
        print(f"{record.id}: {record.service} | {record.username} | {record.password}")
    return 0


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.list:
            return handle_list(args)

        manager = None
        if args.save:
            if not args.service:
                parser.error("--service is required when using --save")
            manager = PasswordManager(args.database, args.key_file)

        if args.passphrase:
            generated_value = generate_passphrase(args.words, args.separator)
            label = "Passphrase"
        else:
            generated_value = generate_password(
                length=args.length,
                use_letters=not args.no_letters,
                use_digits=not args.no_digits,
                use_special=not args.no_special,
            )
            label = "Password"

        bits, rating = describe_entropy(args, generated_value)
        print(f"{label}: {generated_value}")
        print(f"Entropy: {bits:.1f} bits ({rating})")

        if args.copy:
            copied, message = copy_to_clipboard(generated_value)
            print(message)
            if not copied:
                return 1

        if args.save:
            record_id = manager.save_password(args.service, args.username, generated_value)
            print(f"Saved encrypted record #{record_id}.")

        return 0
    except (PasswordGenerationError, EncryptionUnavailableError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
