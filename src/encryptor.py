from pathlib import Path

try:
    from cryptography.fernet import Fernet
except ImportError:  # pragma: no cover - depends on optional runtime install
    Fernet = None


class EncryptionUnavailableError(RuntimeError):
    """Raised when cryptography is required but not installed."""


class Encryptor:
    def __init__(self, key_path="secret.key"):
        if Fernet is None:
            raise EncryptionUnavailableError(
                "Install dependencies with: pip install -r requirements.txt"
            )

        self.key_path = Path(key_path)
        self.key = self._load_or_create_key()
        self.fernet = Fernet(self.key)

    def _load_or_create_key(self):
        if self.key_path.exists():
            return self.key_path.read_bytes()

        key = Fernet.generate_key()
        self.key_path.write_bytes(key)
        return key

    def encrypt(self, value):
        return self.fernet.encrypt(value.encode("utf-8")).decode("utf-8")

    def decrypt(self, token):
        return self.fernet.decrypt(token.encode("utf-8")).decode("utf-8")
