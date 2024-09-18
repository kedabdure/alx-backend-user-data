#!/usr/bin/env python3
""" Module of auth class
"""
from typing import List, TypeVar
from flask import request
from user import User

User = TypeVar('User')


class Auth:
    """Auth class
    """
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """Decide whether a given URL path needs authentication
        """
        return False

    def authorization_header(self, request=None) -> str:
        """Retrieve the Authorization header from an HTTP request
        """
        return None

    def current_user(self, request=None) -> User:
        """Retrieve the current user based on the request.
        """
        return None
