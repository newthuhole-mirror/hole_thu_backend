import time

SQLALCHEMY_DATABASE_URI = 'sqlite:///hole.db'
SQLALCHEMY_TRACK_MODIFICATIONS = False
JSON_AS_ASCII = False
CLIENT_ID = '<id>'
CLIENT_SECRET = '<secret>'
MASTODON_URL = 'https://mastodon.social'
REDIRECT_URI = 'http://hole.thu.monster/_auth'
ADMINS = ['cs_114514']
START_TIME = int(time.time())
ENABLE_TMP = True
RDS_CONFIG = {
    'host': 'localhost',
    'port': 6379,
    'decode_responses': True
}
SEARCH_DB = 'hole_search.db'
EXT_SIMPLE_URL = 'libsimple/libsimple'
