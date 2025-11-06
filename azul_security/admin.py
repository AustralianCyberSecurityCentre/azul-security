"""Provide functionality to verify if a user is an admin or not."""

import functools
from typing import Any

from azul_security.settings import Settings


@functools.lru_cache()
def _get_settings():
    """Return an instance of the azul-security settings class, cached."""
    return Settings()


def is_user_admin(user_info: Any) -> bool:
    """Return true if the user is admin and false if they are not."""
    # user_info is expected to be the models_auth.UserInfo type however we wish to avoid adding another dependency.
    # Unit tests will pick up problems if the underlying model changes.
    for admin_role in _get_settings().admin_roles:
        if admin_role in user_info.roles:
            return True
    return False
