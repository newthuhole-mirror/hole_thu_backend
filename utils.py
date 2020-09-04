import hashlib
from flask import request, abort, current_app
from models import User, Attention, Syslog

def get_config(key):
    return current_app.config.get(key)

def require_token():
    token = request.args.get('user_token')
    u = User.query.filter_by(token=token).first() if token else None
    if Syslog.query.filter_by(log_type='BANNED', name_hash=hash_name(u.name)).first(): abort(403)
    return u if u else abort(401)

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
        } for c in p.comments if not c.deleted
    ]

def check_attention(name, pid):
    at = Attention.query.filter_by(name_hash=hash_name(name), pid=pid, disabled=False).first()
    return 1 if at else 0

def check_can_del(name, author_hash):
    return 1 if hash_name(name) == author_hash or name in get_config('ADMINS') else 0
