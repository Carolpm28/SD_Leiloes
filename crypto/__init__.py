
"""
Package initializer for the local `crypto` package used in this project.
Exposes KeyManager and helper functions from crypto.keys for convenience.

This file ensures `import crypto.keys` and `from crypto import KeyManager` work
when the package is used locally in the project and when tools like Pylance
resolve imports.
"""

from .keys import (
	KeyManager,
	sign_data,
	verify_signature,
	encrypt_data,
	decrypt_data,
)

__all__ = [
	"KeyManager",
	"sign_data",
	"verify_signature",
	"encrypt_data",
	"decrypt_data",
]

