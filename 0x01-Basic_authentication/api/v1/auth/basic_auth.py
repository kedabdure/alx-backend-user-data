#!/usr/bin/env python3
""" Module of Basic Authentication
"""
import base64
from api.v1.auth.auth import Auth
from models.user import User
from typing import Tuple


class BasicAuth(Auth):
    """ Basic Authentication Class """
    def extract_base64_authorization_header(self,
                                            authorization_header: str) -> str:
        """ Extracts base64 Authorization Header """
        if authorization_header is None or type(
                                    authorization_header) is not str:
            return None

        if not authorization_header.startswith("Basic "):
            return None

        return authorization_header[6:]

    def decode_base64_authorization_header(
                self, base64_authorization_header: str) -> str:
        """returns the decoded value of a base64 string
        """
        if base64_authorization_header is None or type(
                                    base64_authorization_header) is not str:
            return None
        try:
            decoded_bytes = base64.b64decode(base64_authorization_header)
            return decoded_bytes.decode('utf-8')
        except Exception:
            return None

    def extract_user_credentials(
            self, decoded_base64_authorization_header: str) -> Tuple[str, str]:
        """return the user email and password from the Base64 decoded Value"""
        if decoded_base64_authorization_header is None or type(
                decoded_base64_authorization_header) is not str:
            return (None, None)
        if ':' not in decoded_base64_authorization_header:
            return (None, None)
        email, password = decoded_base64_authorization_header.split(':', 1)
        return (email, password)

    def user_object_from_credentials(self, user_email: str,
                                     user_pwd: str) -> User:
        """
        Returns the User instance based on his
        email and password
        """
        if user_email is None or not isinstance(user_email, str):
            return None

        if user_pwd is None or not isinstance(user_pwd, str):
            return None

        try:
            found_users = User.search({'email': user_email})
        except Exception:
            return None

        for user in found_users:
            if user.is_valid_password(user_pwd):
                return user

        return None
