#!/usr/bin/env python3
""" Module of Authentication
"""
from flask import request
from typing import List, TypeVar
from models.user import User
from . import Auth


class BasicAuth(Auth):
    """ Class for Basic Authentications
    """
    pass
