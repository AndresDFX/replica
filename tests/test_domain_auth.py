"""Domain: hashing de contraseñas y verificación en tiempo constante."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src", "lambda"))

from domain.auth import gen_code, hash_password, password_valida, verify_password  # noqa: E402


class AuthTests(unittest.TestCase):
    def test_hash_y_verify(self):
        h = hash_password("Tester#12345")
        self.assertTrue(h.startswith("pbkdf2_sha256$"))
        self.assertTrue(verify_password("Tester#12345", h))
        self.assertFalse(verify_password("otra", h))

    def test_hashes_distintos_por_salt(self):
        self.assertNotEqual(hash_password("misma"), hash_password("misma"))
        # pero ambos verifican
        self.assertTrue(verify_password("misma", hash_password("misma")))

    def test_verify_stored_invalido(self):
        for bad in ("", "x", "a$b$c", None, "md5$1$x$y"):
            self.assertFalse(verify_password("x", bad))

    def test_password_valida(self):
        self.assertTrue(password_valida("Montana-Verde-27"))
        self.assertFalse(password_valida("12345678"))  # SEC-10: 12+
        self.assertFalse(password_valida("password1234"))  # comun
        self.assertFalse(password_valida("aaaaaaaaaaaaaa"))  # trivial
        self.assertFalse(password_valida("ana-Montana-27", "ana"))  # contiene el usuario
        self.assertFalse(password_valida("corta"))
        self.assertFalse(password_valida(""))

    def test_gen_code(self):
        c = gen_code(6)
        self.assertEqual(len(c), 6)
        self.assertTrue(c.isdigit())


if __name__ == "__main__":
    unittest.main()
