# -*- coding: utf-8 -*-
ASTERISK_ADDRESS = 'localhost'
ASTERISK_PORT = '5038'
ASTERISK_LOGIN = ''
ASTERISK_PASSWORD = ''
RESOURCE_OWNER_KEY = ''
RESOURCE_OWNER_SECRET = ''
ALLOWED_HOSTS = []

DEBUG = False

API_TIMEOUT = 2

try:
    from local_config import *
except ImportError:
    pass
