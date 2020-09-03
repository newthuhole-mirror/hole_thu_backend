import hashlib
from flask import request, abort
from models import User, Attention

def require_token():
    token = request.args.get('user_token')
    u = User.query.filter_by(token=token).first() if token else None
    return u if u else abort(401)

def map_post(p, name_hash, mc=50):
    return {
            'pid': p.id,
            'likenum': p.likenum,
            'cw': p.cw,
            'text': p.content,
            'timestamp': p.timestamp,
            'type' : p.post_type,
            'url' : p.file_url,
            'reply': len(p.comments),
            'comments': map_comment(p) if len(p.comments) < mc else None,
            'attention': check_attention(name_hash, p.id)
        }

def map_comment(p):

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
        #'cw': None  # comments may have cw in future
        } for c in p.comments
    ]

def check_attention(name_hash, pid):
    at = Attention.query.filter_by(name_hash=name_hash, pid=pid, disabled=False).first()
    return 1 if at else 0
