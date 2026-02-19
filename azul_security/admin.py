"""Provide functionality to verify if a user is an admin or not."""

import functools

from azul_bedrock.models_auth import UserInfo

from azul_security.settings import Settings


@functools.lru_cache()
def _get_settings():
    """Return an instance of the azul-security settings class, cached."""
    return Settings()


def is_admin_roles(roles: str) -> bool:
    """Verify if the list of provided roles contains an admin role."""
    for admin_role in _get_settings().admin_roles:
        if admin_role in roles:
            return True
    return False


def is_user_admin(user_info: UserInfo) -> bool:
    """Return true if the user is admin and false if they are not."""
    return is_admin_roles(user_info.roles)
