#!/usr/bin/env python3
""" Module of Basic Authentication
"""
from api.v1.auth.auth import Auth


class BasicAuth(Auth):
    """ Basic Authentication Class """
    def extract_base64_authorization_header(self, authorization_header: str) -> str:
        """ Extracts base64 Authorization Header """
        if authorization_header is None or type(authorization_header) is not str:
            return None

        if not authorization_header.startswith("Basic "):
            return None

        return authorization_header[6:]

