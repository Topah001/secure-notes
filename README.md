# 44 — Secure Notes

A local, single-user encrypted-notes prototype. `cryptography` Scrypt derives a 256-bit key from the password and a random per-vault salt; AES-GCM encrypts and authenticates the complete notes document using a fresh random nonce on each save. The password is never stored. Wrong passwords, malformed files, and modified ciphertext fail closed; there is no plaintext fallback or recovery path.

## Run

Requires Python 3.10+. Install the documented dependency with `python -m pip install -r requirements.txt`, then run the tested API or `python -m unittest discover -s tests -v`. Example:

```python
from secure_notes import SecureNotes
vault = SecureNotes("notes.vault", input("Vault password: "))
vault.add_note("Title", "Note body")
```

Treat backups and the unlocked process as sensitive. Losing the password means losing the notes. This implementation is a **prototype and has not been security audited**. **Do not use production secrets or rely on it for high-value data.**
