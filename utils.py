import hashlib, time
from flask import request, abort, current_app
from models import User, Attention, Syslog

def get_config(key):
    return current_app.config.get(key)

def tmp_token():
    return hash_name(str(int(time.time() / 900)) + User.query.get(1).token)[5:21]

def require_token():
    token = request.headers.get('User-Token') or request.args.get('user_token')
    if not token: abort(401)

    if len(token.split('_')) == 2 and get_config('ENABLE_TMP'):
        tt, suf = token.split('_')
        if tt != tmp_token(): abort(401)
        return User(name='tmp_'+suf)


    u = User.query.filter_by(token=token).first()
    if not u or Syslog.query.filter_by(log_type='BANNED', name_hash=hash_name(u.name)).first(): abort(401)
    return u

def hash_name(name):
    return hashlib.sha256((get_config('SALT') + name).encode('utf-8')).hexdigest()

def map_post(p, name, mc=50):
    return {
            'pid': p.id,
            'likenum': p.likenum,
            'cw': p.cw,
            'text': p.content,
            'timestamp': p.timestamp,
            'type' : p.post_type,
            'url' : p.file_url,
            'reply': len(p.comments),
            'comments': map_comment(p, name) if len(p.comments) < mc else None,
            'attention': check_attention(name, p.id),
            'can_del': check_can_del(name, p.name_hash)
        }

def map_comment(p, name):

    names = {p.name_hash: 0}

    def gen_name_id(nh):
        if nh not in names:
            names[nh] = len(names)
        return names[nh]
    
    return [{
        'cid': c.id,
        'name_id': gen_name_id(c.name_hash),
        'pid': p.id,
        'text': c.content,
        'timestamp': c.timestamp,
        'can_del': check_can_del(name, c.name_hash)
        } for c in p.comments if not (c.deleted and gen_name_id(c.name_hash)>=0)
    ]

def map_syslog(s):
    return {
            'type': s.log_type,
            'detail': s.log_detail,
            'user': look(s.name_hash),
            'timestamp': s.timestamp
        }

def check_attention(name, pid):
    at = Attention.query.filter_by(name_hash=hash_name(name), pid=pid, disabled=False).first()
    return 1 if at else 0

def check_can_del(name, author_hash):
    return 1 if hash_name(name) == author_hash or name in get_config('ADMINS') else 0

def look(s):
    return s[:3] + '...' + s[-3:]

def get_num(p):
    if not (p and p.isdigit()): abort(422)
    return int(p)
