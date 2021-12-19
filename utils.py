import hashlib
import time
import redis
from datetime import date

from flask import request, abort, current_app
from models import User, Attention, Syslog
from config import RDS_CONFIG, ADMINS, ENABLE_TMP

RDS_KEY_POLL_OPTS = 'hole_thu:poll_opts:%s'
RDS_KEY_POLL_VOTES = 'hole_thu:poll_votes:%s:%s'

rds = redis.Redis(**RDS_CONFIG)


def get_config(key):
    return current_app.config.get(key)


def is_admin(name):
    return name in ADMINS


def tmp_token():
    return hash_name(
        str(int(time.time() / 900)) + User.query.get(1).token
    )[5:21]


def get_current_username():
    token = request.headers.get('User-Token') or request.args.get('user_token')
    if not token:
        abort(401)

    if len(token.split('_')) == 2 and ENABLE_TMP:
        tt, suf = token.split('_')
        if tt != tmp_token():
            abort(401)
        return 'tmp_' + suf

    u = User.query.filter_by(token=token).first()
    if not u or Syslog.query.filter_by(
            log_type='BANNED', name_hash=hash_name(u.name)).first():
        abort(401)
    return u.name


def hash_name(name):
    return hashlib.sha256(
        (get_config('SALT') + name).encode('utf-8')
    ).hexdigest()


def map_post(p, name, mc=50):
    r = {
        'pid': p.id,
        'likenum': p.likenum,
        'cw': p.cw,
        'text': p.content,
        'timestamp': p.timestamp,
        'type': p.post_type,
        'url': p.file_url,
        'reply': len(p.comments),
        'comments': map_comment(p, name) if len(p.comments) < mc else None,
        'attention': check_attention(name, p.id),
        'can_del': check_can_del(name, p.name_hash),
        'allow_search': bool(p.search_text),
        'poll': gen_poll_dict(p.id, name)
    }
    if is_admin(name):
        r['hot_score'] = p.hot_score

    return r


def gen_poll_dict(pid, name):
    if not rds.exists(RDS_KEY_POLL_OPTS % pid):
        return None
    name = name_with_tmp_limit(name)
    vote = None
    answers = []
    for idx, opt in enumerate(rds.lrange(RDS_KEY_POLL_OPTS % pid, 0, -1)):
        answers.append({
            'option': opt,
            'votes': rds.scard(RDS_KEY_POLL_VOTES % (pid, idx))
        })
        if rds.sismember(RDS_KEY_POLL_VOTES % (pid, idx), hash_name(name)):
            vote = opt

    return {
        'answers': answers,
        'vote': vote
    }


def name_with_tmp_limit(name: str) -> str:
    return 'tmp:%s' % date.today() if name.startswith(
        'tmp_') else name


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
    } for c in p.comments if not (c.deleted and gen_name_id(c.name_hash) >= 0)
    ]


def map_syslog(s, username):
    return {
        'type': s.log_type,
        'detail': s.log_detail if check_can_del(username, s.name_hash) else '',
        'user': look(s.name_hash),
        'timestamp': s.timestamp
    }


def check_attention(name, pid):
    at = Attention.query.filter_by(
        name_hash=hash_name(name),
        pid=pid,
        disabled=False).first()
    return 1 if at else 0


def check_can_del(name, author_hash):
    return hash_name(name) == author_hash or is_admin(name)


def look(s):
    return s[:3] + '...' + s[-3:]


def get_num(p):
    if not (p and p.isdigit()):
        abort(422)
    return int(p)
