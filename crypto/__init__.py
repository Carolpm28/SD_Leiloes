#package initializer para o pacote local `crypto` usado neste projeto.Expõe KeyManager e funções auxiliares de crypto.keys para conveniência.
#Este arquivo garante que `import crypto.keys` e `from crypto import KeyManager` funcionem 
# quando o pacote for usado localmente no projeto e quando ferramentas como Pylance resolverem importações.

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

