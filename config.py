# -*- coding: utf-8 -*-
ASTERISK_ADDRESS = ''
ASTERISK_PORT = ''
ASTERISK_LOGIN = ''
ASTERISK_PASSWORD = ''
AUTH_TOKEN = ''

try:
    from local_config import *
except ImportError:
    pass
