"""Autenticación: hash de contraseñas (PBKDF2-HMAC-SHA256) y códigos de reseteo.

Puro y sin dependencias externas (solo stdlib). El hash se guarda como
``pbkdf2_sha256$<iter>$<salt_b64>$<hash_b64>`` y se verifica en tiempo constante.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets

_ALGO = "pbkdf2_sha256"
_ITERS = 200_000
_MIN_LEN = 12  # SEC-10 (ASVS 2.1.1): 12+; antes 8

# Lista corta de contraseñas/raíces más filtradas (se compara normalizada y sin dígitos finales).
# Local a propósito: no enviar nada de la contraseña a terceros.
_COMUNES = frozenset("""
password contrasena contraseña qwerty qwertyuiop asdfghjkl zxcvbnm abc123 abcdef 123456789 1234567890
iloveyou admin administrador welcome bienvenido letmein monkey dragon football futbol colombia
replica telegram whatsapp passw0rd p@ssw0rd changeme cambiame secreto
""".split())


def motivo_password(password: str, usuario: str = "") -> str:
    """Por qué la contraseña NO cumple la política ("" si cumple). Mensajes listos para la UI."""
    if not isinstance(password, str) or len(password) < _MIN_LEN:
        return f"La contraseña debe tener al menos {_MIN_LEN} caracteres."
    base = password.lower().rstrip("0123456789!.*#@$ ")
    if base in _COMUNES or password.lower() in _COMUNES:
        return "Esa contraseña es de las más usadas y filtradas; elige otra."
    if len(set(password)) < 5:
        return "La contraseña repite demasiado los mismos caracteres; elige otra."
    u = (usuario or "").strip().lower()
    if len(u) >= 3 and u in password.lower():
        return "La contraseña no puede contener tu nombre de usuario."
    return ""


def password_valida(password: str, usuario: str = "") -> bool:
    """Política: 12+ caracteres, no común, no trivial, sin el usuario dentro."""
    return motivo_password(password, usuario) == ""


def hash_password(password: str, iterations: int = _ITERS) -> str:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"{_ALGO}${iterations}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iters, salt_b64, hash_b64 = str(stored).split("$")
        if algo != _ALGO:
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(hash_b64)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(iters))
        return hmac.compare_digest(dk, expected)
    except Exception:
        return False


def gen_code(n: int = 6) -> str:
    """Código numérico aleatorio de n dígitos (para reseteo de contraseña).

    B1: usa secrets.randbelow(10) por dígito (uniforme). Antes ``os.urandom % 10`` tenía sesgo de
    módulo (256 no es múltiplo de 10): los dígitos 0-5 salían ~4% más que 6-9, restando entropía."""
    return "".join(str(secrets.randbelow(10)) for _ in range(n))
