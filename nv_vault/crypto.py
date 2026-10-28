import os
import json
import struct
import base64
import time
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from argon2.low_level import hash_secret_raw, Type

MAGIC_BYTES = b"NVLT"
FORMAT_VERSION = 1

class CryptoEngine:
    @staticmethod
    def derive_key_argon2id(password: str, salt: bytes) -> bytes:
        """Derives a 32-byte P.Key from password and 16-byte salt using Argon2id."""
        return hash_secret_raw(
            secret=password.encode("utf-8"),
            salt=salt,
            time_cost=3,
            memory_cost=65536,  # 64 MB
            parallelism=4,
            hash_len=32,
            type=Type.ID
        )

    @staticmethod
    def generate_key() -> bytes:
        """Generates a random 256-bit (32-byte) key."""
        return AESGCM.generate_key(bit_length=256)

    @staticmethod
    def _clean_hex(hex_str: str) -> bytes:
        cleaned = hex_str.strip().replace(" ", "").replace("-", "")
        if len(cleaned) != 64:
            raise ValueError(f"Expected 64 hex characters (32 bytes), got {len(cleaned)}.")
        return bytes.fromhex(cleaned)

    @staticmethod
    def encrypt_to_nv(filepath: Path, out_dir: Path, m_key: bytes) -> tuple[Path, str]:
        """
        Encrypts a regular file into a .nv container.
        Returns (output_nv_path, hex_encoded_i_key).
        """
        plaintext = filepath.read_bytes()
        i_key = CryptoEngine.generate_key()

        # 1. Wrap I.Key with M.Key (Key Envelope)
        wrap_nonce = os.urandom(12)
        wrapped_ikey = AESGCM(m_key).encrypt(wrap_nonce, i_key, None)

        # 2. Prepare Metadata Header
        payload_nonce = os.urandom(12)
        ext = filepath.suffix.lower()
        header_dict = {
            "orig_name": filepath.name,
            "ext": ext,
            "size": len(plaintext),
            "created_at": int(time.time()),
            "wrap_nonce": base64.b64encode(wrap_nonce).decode("ascii"),
            "wrapped_ikey": base64.b64encode(wrapped_ikey).decode("ascii"),
            "payload_nonce": base64.b64encode(payload_nonce).decode("ascii"),
        }
        header_bytes = json.dumps(header_dict).encode("utf-8")

        # 3. Encrypt Payload with I.Key (bind header_bytes as AAD so metadata cannot be tampered with)
        ciphertext = AESGCM(i_key).encrypt(payload_nonce, plaintext, header_bytes)

        # 4. Pack binary .nv container
        out_path = out_dir / (filepath.stem + ".nv")
        counter = 1
        while out_path.exists():
            out_path = out_dir / f"{filepath.stem}_{counter}.nv"
            counter += 1

        with open(out_path, "wb") as f:
            f.write(MAGIC_BYTES)
            f.write(struct.pack(">BI", FORMAT_VERSION, len(header_bytes)))
            f.write(header_bytes)
            f.write(ciphertext)

        return out_path, i_key.hex()

    @staticmethod
    def read_header_only(nv_path: Path) -> dict:
        """Fast metadata parser for Nautilus gallery view without decrypting full payload."""
        with open(nv_path, "rb") as f:
            prefix = f.read(9)
            if len(prefix) < 9 or prefix[:4] != MAGIC_BYTES:
                raise ValueError("Invalid .nv file (Magic bytes mismatch)")
            version, header_len = struct.unpack(">BI", prefix[4:9])
            if version != FORMAT_VERSION:
                raise ValueError(f"Unsupported .nv version: {version}")
            header_bytes = f.read(header_len)
            return json.loads(header_bytes.decode("utf-8"))

    @staticmethod
    def decrypt_nv_with_mkey(nv_path: Path, m_key: bytes) -> tuple[dict, bytes, str]:
        """Unlocks a .nv file using the Vault's Master Key (M.Key)."""
        header_dict, header_bytes, ciphertext = CryptoEngine._parse_nv(nv_path)

        wrap_nonce = base64.b64decode(header_dict["wrap_nonce"])
        wrapped_ikey = base64.b64decode(header_dict["wrapped_ikey"])

        # Unwrap I.Key using M.Key
        i_key = AESGCM(m_key).decrypt(wrap_nonce, wrapped_ikey, None)

        # Decrypt file payload using I.Key
        payload_nonce = base64.b64decode(header_dict["payload_nonce"])
        plaintext = AESGCM(i_key).decrypt(payload_nonce, ciphertext, header_bytes)

        return header_dict, plaintext, i_key.hex()

    @staticmethod
    def decrypt_nv_with_ikey(nv_path: Path, i_key_hex: str) -> tuple[dict, bytes]:
        """Unlocks a shared .nv file directly using its Individual Key (I.Key)."""
        i_key = CryptoEngine._clean_hex(i_key_hex)
        header_dict, header_bytes, ciphertext = CryptoEngine._parse_nv(nv_path)

        payload_nonce = base64.b64decode(header_dict["payload_nonce"])
        plaintext = AESGCM(i_key).decrypt(payload_nonce, ciphertext, header_bytes)
        return header_dict, plaintext

    @staticmethod
    def _parse_nv(nv_path: Path):
        data = nv_path.read_bytes()
        if len(data) < 9 or data[:4] != MAGIC_BYTES:
            raise ValueError("Invalid .nv file (Magic bytes mismatch)")
        version, header_len = struct.unpack(">BI", data[4:9])
        if version != FORMAT_VERSION:
            raise ValueError(f"Unsupported .nv version: {version}")
        if len(data) < 9 + header_len:
            raise ValueError("Corrupted .nv file (Truncated header)")
        header_bytes = data[9:9 + header_len]
        ciphertext = data[9 + header_len:]
        header_dict = json.loads(header_bytes.decode("utf-8"))
        return header_dict, header_bytes, ciphertext
