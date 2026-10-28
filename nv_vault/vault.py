import os
import json
import base64
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from .crypto import CryptoEngine

class VaultManager:
    def __init__(self, vault_dir: Path):
        self.vault_dir = vault_dir
        self.vault_dir.mkdir(parents=True, exist_ok=True)
        self.config_file = self.vault_dir / "vault_config.json"
        self.m_key: bytes | None = None

    def set_directory(self, new_dir: Path):
        self.vault_dir = new_dir
        self.vault_dir.mkdir(parents=True, exist_ok=True)
        self.config_file = self.vault_dir / "vault_config.json"
        self.m_key = None

    def is_initialized(self) -> bool:
        return self.config_file.exists()

    def setup_vault(self, password: str, existing_mkey_hex: str | None = None) -> str:
        """Creates a new vault or imports an existing M.Key, secured with Argon2id."""
        salt = os.urandom(16)
        p_key = CryptoEngine.derive_key_argon2id(password, salt)

        if existing_mkey_hex:
            self.m_key = CryptoEngine._clean_hex(existing_mkey_hex)
        else:
            self.m_key = CryptoEngine.generate_key()

        self._save_encrypted_mkey(p_key, salt, self.m_key)
        return self.m_key.hex()

    def import_mkey_with_password(self, password: str, new_mkey_hex: str) -> str:
        """Updates the vault's Master Key (M.Key) from Settings for device migration."""
        new_mkey = CryptoEngine._clean_hex(new_mkey_hex)
        salt = os.urandom(16)
        p_key = CryptoEngine.derive_key_argon2id(password, salt)
        self.m_key = new_mkey
        self._save_encrypted_mkey(p_key, salt, self.m_key)
        return self.m_key.hex()

    def _save_encrypted_mkey(self, p_key: bytes, salt: bytes, m_key: bytes):
        nonce = os.urandom(12)
        encrypted_mkey = AESGCM(p_key).encrypt(nonce, m_key, None)
        config = {
            "salt": base64.b64encode(salt).decode("ascii"),
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "encrypted_mkey": base64.b64encode(encrypted_mkey).decode("ascii")
        }
        self.config_file.write_text(json.dumps(config, indent=2))

    def unlock_vault(self, password: str) -> bool:
        """Derives P.Key from password and decrypts M.Key into memory."""
        try:
            config = json.loads(self.config_file.read_text())
            salt = base64.b64decode(config["salt"])
            nonce = base64.b64decode(config["nonce"])
            encrypted_mkey = base64.b64decode(config["encrypted_mkey"])

            p_key = CryptoEngine.derive_key_argon2id(password, salt)
            self.m_key = AESGCM(p_key).decrypt(nonce, encrypted_mkey, None)
            return True
        except (InvalidTag, Exception):
            return False

    def lock(self):
        """Clears M.Key from memory."""
        self.m_key = None
