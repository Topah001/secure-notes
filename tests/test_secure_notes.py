import json
import tempfile
import unittest
from pathlib import Path

from secure_notes import SecureNotes, VaultError


class SecureNotesTests(unittest.TestCase):
    def test_round_trip_and_encrypted_storage(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "notes.vault"
            vault = SecureNotes(path, "correct horse")
            note_id = vault.add_note("Private title", "Secret note body")
            raw = path.read_text(encoding="utf-8")
            self.assertNotIn("Secret note body", raw)
            reopened = SecureNotes(path, "correct horse")
            self.assertEqual(reopened.list_notes(), [{"id": note_id, "title": "Private title", "body": "Secret note body"}])

    def test_wrong_password_fails_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "notes.vault"
            SecureNotes(path, "right").add_note("t", "b")
            with self.assertRaises(VaultError):
                SecureNotes(path, "wrong")

    def test_modified_ciphertext_fails_authentication(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "notes.vault"
            SecureNotes(path, "password").add_note("t", "b")
            data = json.loads(path.read_text(encoding="utf-8"))
            encoded = data["ciphertext"]
            data["ciphertext"] = ("A" if encoded[0] != "A" else "B") + encoded[1:]
            path.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaises(VaultError):
                SecureNotes(path, "password")

    def test_random_salt_and_nonce_on_each_save(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "notes.vault"
            vault = SecureNotes(path, "password")
            first = json.loads(path.read_text(encoding="utf-8"))
            vault.add_note("t", "b")
            second = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(first["salt"], second["salt"])
            self.assertNotEqual(first["nonce"], second["nonce"])


if __name__ == "__main__":
    unittest.main()
