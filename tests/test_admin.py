import unittest

from azul_bedrock.models_auth import UserInfo
from fastapi import Request

from azul_security.admin import is_user_admin

from . import support


class TestAdmin(unittest.TestCase):

    @classmethod
    def alter_environment(cls):
        support.resetEnv()

    def setUp(self) -> None:
        self.alter_environment()
        return super().setUp()

    @staticmethod
    def _create_user_info(token_roles: list[str]) -> Request:
        """Create a mock UserInfo."""
        return UserInfo(
            username="llama",
            org="test",
            email="",
            roles=token_roles,
            unique_id="llama-subject-id",
        )

    def test_admin_user(self):
        self.assertTrue(is_user_admin(self._create_user_info(["admin"])))

    def test_not_admin_user(self):
        self.assertFalse(is_user_admin(self._create_user_info(["validated"])))

    def test_not_label_admin_user(self):
        self.assertFalse(is_user_admin(self._create_user_info([])))
