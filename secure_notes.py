"""Encrypted local notes. This prototype has not been security audited."""

import base64
import json
import os
import tempfile
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


_FORMAT = "secure-notes-v1"
_AAD = b"secure-notes-v1"


class VaultError(Exception):
    """Raised when a vault cannot be safely opened or written."""


def _derive_key(password: str, salt: bytes) -> bytes:
    if not isinstance(password, str) or not password:
        raise ValueError("A non-empty password is required")
    return Scrypt(salt=salt, length=32, n=2**14, r=8, p=1).derive(password.encode("utf-8"))


def _b64decode(value: object) -> bytes:
    if not isinstance(value, str):
        raise VaultError("Invalid vault format")
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise VaultError("Invalid vault format") from exc


class SecureNotes:
    """Single-user encrypted notes persisted as one authenticated vault."""

    def __init__(self, path: str | Path, password: str):
        self.path = Path(path)
        self._key: bytes | None = None
        self._notes: list[dict[str, str]] = []
        if self.path.exists():
            self._load(password)
        else:
            self._salt = os.urandom(16)
            self._key = _derive_key(password, self._salt)
            self.save()

    def _load(self, password: str) -> None:
        try:
            envelope = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(envelope, dict) or envelope.get("format") != _FORMAT:
                raise VaultError("Unsupported or invalid vault format")
            salt = _b64decode(envelope.get("salt"))
            nonce = _b64decode(envelope.get("nonce"))
            ciphertext = _b64decode(envelope.get("ciphertext"))
            if len(salt) != 16 or len(nonce) != 12:
                raise VaultError("Invalid vault format")
            key = _derive_key(password, salt)
            plaintext = AESGCM(key).decrypt(nonce, ciphertext, _AAD)
            notes = json.loads(plaintext.decode("utf-8"))
            if not isinstance(notes, list) or any(
                not isinstance(note, dict)
                or set(note) != {"id", "title", "body"}
                or any(not isinstance(note[field], str) for field in ("id", "title", "body"))
                for note in notes
            ):
                raise VaultError("Invalid encrypted note data")
        except InvalidTag as exc:
            raise VaultError("Vault authentication failed (wrong password or modified data)") from exc
        except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
            raise VaultError("Could not safely open vault") from exc
        self._salt, self._key, self._notes = salt, key, notes

    def save(self) -> None:
        if self._key is None:
            raise VaultError("Vault is not open")
        nonce = os.urandom(12)
        ciphertext = AESGCM(self._key).encrypt(
            nonce, json.dumps(self._notes, ensure_ascii=False).encode("utf-8"), _AAD
        )
        envelope = {
            "format": _FORMAT,
            "salt": base64.b64encode(self._salt).decode("ascii"),
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temp_name = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", dir=self.path.parent, delete=False
            ) as temp_file:
                temp_name = temp_file.name
                json.dump(envelope, temp_file)
                temp_file.flush()
                os.fsync(temp_file.fileno())
            os.replace(temp_name, self.path)
        except OSError as exc:
            if temp_name and os.path.exists(temp_name):
                os.unlink(temp_name)
            raise VaultError("Could not safely save vault") from exc

    def list_notes(self) -> list[dict[str, str]]:
        return [note.copy() for note in self._notes]

    def add_note(self, title: str, body: str) -> str:
        if not isinstance(title, str) or not title.strip() or not isinstance(body, str):
            raise ValueError("A non-empty title and text body are required")
        note_id = os.urandom(16).hex()
        self._notes.append({"id": note_id, "title": title.strip(), "body": body})
        self.save()
        return note_id

    def update_note(self, note_id: str, title: str, body: str) -> None:
        if not isinstance(title, str) or not title.strip() or not isinstance(body, str):
            raise ValueError("A non-empty title and text body are required")
        for note in self._notes:
            if note["id"] == note_id:
                note.update(title=title.strip(), body=body)
                self.save()
                return
        raise KeyError("Note not found")

    def delete_note(self, note_id: str) -> None:
        remaining = [note for note in self._notes if note["id"] != note_id]
        if len(remaining) == len(self._notes):
            raise KeyError("Note not found")
        self._notes = remaining
        self.save()
