from flask import Flask, request, render_template, send_from_directory, abort, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from mastodon import Mastodon
import re, random, string, datetime, hashlib

from models import db, User, Post, Comment, Attention, TagRecord, Syslog
from utils import require_token, map_post, map_comment, map_syslog, check_attention, hash_name, look, get_num, tmp_token

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///hole.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JSON_AS_ASCII'] = False
app.config.from_pyfile('config.py')

db.init_app(app)

with app.app_context():
    db.create_all()

CS_LOGIN_URL = Mastodon(api_base_url=app.config['MASTODON_URL']) \
                .auth_request_url(
                    client_id = app.config['CLIENT_ID'],
                    redirect_uris = app.config['REDIRECT_URI'],
                    scopes = ['read:accounts']
                )

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["1000 / hour"],
)

PER_PAGE = 50

@app.route('/_login')
@limiter.limit("5 / minute")
def login():
    provider = request.args.get('p')
    if(provider == 'cs'):
        return redirect(CS_LOGIN_URL)

    abort(404)

@app.route('/_auth')
@limiter.limit("5 / minute")
def auth():
    # Currently, only for closed.social
    code = request.args.get('code')
    client = Mastodon(
            client_id = app.config['CLIENT_ID'],
            client_secret = app.config['CLIENT_SECRET'],
            api_base_url = app.config['MASTODON_URL']
            )
    token = client.log_in(
            code=code,
            redirect_uri=app.config['REDIRECT_URI'],
            scopes=['read:accounts']
            )
    info = client.account_verify_credentials()

    name = 'cs_' + str(info.id)

    u = v = User.query.filter_by(name=name).first()

    if not u:
        u = User(name=name)
        db.session.add(u)

    if not v or False: #TODO: reset token
        u.token = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
        db.session.commit()

    return redirect('/?token='+ u.token)

@app.route('/_api/v1/getlist')
def get_list():
    u = require_token()

    p = get_num(request.args.get('p'))

    posts = Post.query.filter_by(deleted=False)
    if 'no_cw' in request.args:
        posts = posts.filter_by(cw=None)
    posts = posts.order_by(db.desc('timestamp')).paginate(p, PER_PAGE)

    data =list(map(map_post, posts.items, [u.name] * len(posts.items)))

    return {
            'code': 0,
            'count': len(data),
            'data': data
            }
@app.route('/_api/v1/getone')
def get_one():
    u = require_token()
    
    pid = get_num(request.args.get('pid'))

    post = Post.query.get(pid)
    if not post: abort(404)
    if post.deleted: abort(451)

    data = map_post(post, u.name)

    return {
            'code': 0,
            'data': data
            }

@app.route('/_api/v1/search')
def search():
    u = require_token()

    page     = get_num(request.args.get('page'))
    pagesize = max(get_num(request.args.get('pagesize')), 200)
    keywords = request.args.get('keywords')

    pids = [tr.pid for tr in TagRecord.query.filter_by(tag=keywords).order_by(db.desc('pid')).paginate(page, pagesize).items]

    data = [ map_post(Post.query.get(pid), u.name)
                for pid in pids if Post.query.get(pid) and not Post.query.get(pid).deleted
        ]

    return {
            'code': 0,
            'count': len(data),
            'data': data
            }



@app.route('/_api/v1/dopost', methods=['POST'])
@limiter.limit("50 / hour; 1 / 3 second")
def do_post():
    u = require_token()

    content = request.form.get('text')
    content =  content.strip() if content else None
    content = '[tmp]\n' + content if u.name[:4] == 'tmp_' else content
    post_type = request.form.get('type')
    cw = request.form.get('cw')
    cw =  cw.strip() if cw else None

    if not content or len(content) > 4096: abort(422)
    if cw and len(cw)>32: abort(422)

    p = Post(
            name_hash = hash_name(u.name),
            content = content,
            post_type = post_type,
            cw = cw or None,
            likenum = 1,
            comments = []
            )

    if post_type == 'text':
        pass
    elif post_type == 'image':
        # TODO
        p.file_url = 'foo bar'
    else:
        abort(422)

    db.session.add(p)
    db.session.commit()

    tags = re.findall('(^|\s)#([^#\s]{1,32})', content)
    #print(tags)
    for t in tags:
        tag = t[1]
        if not re.match('\d+', tag):
            db.session.add(TagRecord(tag=tag, pid=p.id))

    db.session.add(Attention(name_hash=hash_name(u.name), pid=p.id))
    db.session.commit()

    return {
            'code': 0,
            'date': p.id
            }

@app.route('/_api/v1/getcomment')
def get_comment():
    u = require_token()

    pid = get_num(request.args.get('pid'))

    post = Post.query.get(pid)
    if not post: abort(404)
    if post.deleted: abort(451)

    data = map_comment(post, u.name)
    
    return {
            'code': 0,
            'attention': check_attention(u.name, pid),
            'likenum': post.likenum,
            'data': data
            }

@app.route('/_api/v1/docomment', methods=['POST'])
@limiter.limit("50 / hour; 1 / 3 second")
def do_comment():
    u = require_token()

    pid = get_num(request.form.get('pid'))

    post = Post.query.get(pid)
    if not post: abort(404)
    if post.deleted: abort(451)

    content = request.form.get('text')
    content =  content.strip() if content else None
    content = '[tmp]\n' + content if u.name[:4] == 'tmp_' else content
    if not content or len(content) > 4096: abort(422)

    c = Comment(
            name_hash = hash_name(u.name),
            content = content,
            )
    post.comments.append(c)
    db.session.commit()

    return {
            'code': 0,
            'data': pid
            }

@app.route('/_api/v1/attention', methods=['POST'])
@limiter.limit("200 / hour; 1 / second")
def attention():
    u = require_token()
    if u.name[:4] == 'tmp_': abort(403)

    s = request.form.get('switch')
    if s not in ['0', '1']: abort(422)

    pid = get_num(request.form.get('pid'))
    
    post = Post.query.get(pid)
    if not post: abort(404)

    at = Attention.query.filter_by(name_hash=hash_name(u.name), pid=pid).first()

    if not at:
        at = Attention(name_hash=hash_name(u.name), pid=pid, disabled=True)
        db.session.add(at)

    print(at.disabled, s=='0')

    if(at.disabled != (s == '0')):
        at.disabled = (s == '0')
        post.likenum += 1 - 2 * int(s == '0');
        db.session.commit()

    return {
            'code': 0,
            'likenum': post.likenum,
            'attention': (s=='1')
            }

@app.route('/_api/v1/getattention')
def get_attention():
    u = require_token()

    ats = Attention.query.filter_by(name_hash=hash_name(u.name), disabled=False)

    posts = [Post.query.get(at.pid) for at in ats.all()]
    data = [ map_post(post, u.name, 10)
            for post in posts[::-1]
                    if post and not post.deleted
        ]

    return {
            'code': 0,
            'count': len(data),
            'data': data
        }

@app.route('/_api/v1/delete', methods=['POST'])
@limiter.limit("50 / hour; 1 / 3 second")
def delete():
    u = require_token()

    obj_type = request.form.get('type')
    obj_id = get_num(request.form.get('id'))
    note = request.form.get('note')

    if note and len(note)>100: abort(422)

    obj = None
    if obj_type == 'pid':
        obj = Post.query.get(obj_id)
    elif obj_type == 'cid':
        obj = Comment.query.get(obj_id)
    if not obj: abort(404)

    if obj.name_hash == hash_name(u.name):
        if obj_type == 'pid':
            if len(obj.comments): abort(403)
            Attention.query.filter_by(pid=obj.id).delete()
            TagRecord.query.filter_by(pid=obj.id).delete()
        db.session.delete(obj)
    elif u.name in app.config.get('ADMINS'):
        obj.deleted = True
        db.session.add(Syslog(
            log_type='ADMIN DELETE',
            log_detail=f"{obj_type}={obj_id}\n{note}",
            name_hash=hash_name(u.name)
            ))
        if note.startswith('!ban'):
            db.session.add(Syslog(
                log_type='BANNED',
                log_detail=f"=> {obj_type}={obj_id}",
                name_hash=obj.name_hash
                ))
    else:
        abort(403)

    db.session.commit()
    return {'code': 0}

@app.route('/_api/v1/systemlog')
def system_log():
    u = require_token()

    ss = Syslog.query.order_by(db.desc('timestamp')).limit(100).all()

    return {
            'start_time': app.config['START_TIME'],
            'salt': look(app.config['SALT']),
            'tmp_token': tmp_token(),
            'data' : list(map(map_syslog, ss))
        }

@app.route('/_api/v1/report', methods=['POST'])
@limiter.limit("50 / hour; 1 / 3 second")
def report():
    u = require_token()

    pid = get_num(request.form.get('pid'))

    reason = request.form.get('reason', '')

    db.session.add(Syslog(
            log_type='REPORT',
            log_detail=f"pid={pid}\n{reason}",
            name_hash=hash_name(u.name)
        ))
    db.session.commit()

    return {'code': 0}


if __name__ == '__main__':
    app.run(debug=True)

