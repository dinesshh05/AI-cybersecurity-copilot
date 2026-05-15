from __future__ import annotations

import unittest

from app.core.auth import CurrentUser, create_access_token, decode_access_token, hash_password, permissions_for_role, verify_password


class AuthTests(unittest.TestCase):
    def test_password_hash_roundtrip(self) -> None:
        password_hash = hash_password("super-secret")
        self.assertTrue(verify_password("super-secret", password_hash))
        self.assertFalse(verify_password("wrong-password", password_hash))

    def test_token_roundtrip(self) -> None:
        user = CurrentUser(
            username="analyst",
            role="analyst",
            display_name="SOC Analyst",
            permissions=permissions_for_role("analyst"),
        )
        token = create_access_token(user)
        decoded = decode_access_token(token)

        self.assertEqual(decoded.username, "analyst")
        self.assertEqual(decoded.role, "analyst")
        self.assertIn("cases.read", decoded.permissions)


if __name__ == "__main__":
    unittest.main()
