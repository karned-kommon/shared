import logging
from fastapi import status, Request, HTTPException
from functools import wraps
from typing import List

from config.config import API_NAME


def check_roles(api_roles: dict, app_roles: dict, permissions: List[str]) -> None:
    required_permissions = []
    for perm in permissions:
        if "/" in perm:
            required_permissions.append(perm)
        else:
            required_permissions.append(f"{API_NAME}/{perm}")

    formatted_roles = []
    if api_roles:
        for api, roles in api_roles.items():
            for role in roles:
                formatted_roles.append(f"{api}/{role}")
    if app_roles:
        for app, roles in app_roles.items():
            for role in roles:
                formatted_roles.append(f"{app}/{role}")

    if not any(perm in formatted_roles for perm in required_permissions):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions ! "
                   "Need : " + ", ".join(required_permissions) +
                   " / Got : " + ", ".join(formatted_roles)
        )


def check_permissions(permissions: List[str]):
    def decorator(func):
        @wraps(func)
        async def wrapper(request: Request, *args, **kwargs):
            logging.info(f"Checking permissions {permissions}")
            logging.info(f"User: {request}")
            token_info = request.state.token_info
            check_roles(token_info.get('api_roles'), token_info.get('app_roles'), permissions)
            return await func(request, *args, **kwargs)
        return wrapper
    return decorator
