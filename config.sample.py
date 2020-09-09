import random, string, time

SQLALCHEMY_DATABASE_URI='sqlite:///hole.db'
SQLALCHEMY_TRACK_MODIFICATIONS=False
JSON_AS_ASCII=False
CLIENT_ID='<id>'
CLIENT_SECRET='<secret>'
MASTODON_URL='https://thu.closed.social'
REDIRECT_URI = 'http://hole.thu.monster/_auth'
THUHOLE_ADDRESS='https://thuhole.com'
THUHOLE_HOST='thuhole.com'
THUHOLE_PID=1
SALT = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
ADMINS = ['cs_114514']
START_TIME = int(time.time())
ENABLE_TMP = True
