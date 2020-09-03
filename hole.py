from flask import Flask, request, render_template, send_from_directory, abort, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from mastodon import Mastodon
import time, re, random, string, datetime, hashlib

from models import db, User, Post, Comment, Attention
from utils import require_token, map_post, map_comment, check_attention

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
PER_PAGE = 25

def hash_name(name):
    return hashlib.sha256((app.config['SALT'] + name).encode('utf-8')).hexdigest()

@app.route('/_login')
def login():
    provider = request.args.get('p')
    if(provider == 'cs'):
        return redirect(CS_LOGIN_URL)

    abort(404)

@app.route('/_auth')
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

    p = request.args.get('p')
    p = int(p) if p and p.isdigit() else -1

    posts = Post.query.filter_by(deleted=False).order_by(db.desc('timestamp')).paginate(page=p, per_page=PER_PAGE)
    

    data =list(map(map_post, posts.items, [hash_name(u.name)] * len(posts.items)))

    return {
            'code': 0,
            'count': len(data),
            'data': data
            }
@app.route('/_api/v1/getone')
def get_one():
    u = require_token()
    
    pid = request.args.get('pid')
    pid = int(pid) if pid and pid.isdigit() else -1

    post = Post.query.get(pid)
    if not post: abort(404)
    if post.deleted: abort(451)

    data = map_post(post, name_hash=hash_name(u.name))

    return {
            'code': 0,
            'data': data
            }


@app.route('/_api/v1/dopost', methods=['POST'])
def do_post():
    u = require_token()

    content = request.form.get('text')
    content =  content.strip() if content else None
    post_type = request.form.get('type')
    cw = request.form.get('cw')
    cw =  cw.strip() if cw else None

    print(content, post_type, cw)

    if not content or len(content) > 4096: abort(422)
    if cw and len(cw)>32: abort(422)

    p = Post(
            name_hash = hash_name(u.name),
            content = content,
            post_type = post_type,
            cw = cw or None,
            timestamp = int(time.time()),
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
    
    db.session.add(Attention(name_hash=hash_name(u.name), pid=p.id))
    db.session.commit()

    return {
            'code': 0,
            'date': p.id
            }

@app.route('/_api/v1/getcomment')
def get_comment():
    u = require_token()

    pid = request.args.get('pid')
    if pid and pid.isdigit():
        p = int(pid)
    else:
        abort(422)

    post = Post.query.get(pid)
    if not post: abort(404)
    
    data = map_comment(post)
    
    return {
            'code': 0,
            'attention': check_attention(hash_name(u.name), pid),
            'data': data
            }

@app.route('/_api/v1/docomment', methods=['POST'])
def do_comment():
    u = require_token()

    pid = request.form.get('pid')
    if pid and pid.isdigit():
        p = int(pid)
    else:
        abort(422)

    post = Post.query.get(pid)
    if not post: abort(404)

    content = request.form.get('text')
    content =  content.strip() if content else None
    if not content or len(content) > 4096: abort(422)

    c = Comment(
            name_hash = hash_name(u.name),
            content = content,
            timestamp = int(time.time())
            )
    post.comments.append(c)
    db.session.commit()

    return {
            'code': 0,
            'data': pid
            }

@app.route('/_api/v1/attention', methods=['POST'])
def attention():
    u = require_token()
    
    s = request.form.get('switch')
    if s not in ['0', '1']: abort(422)

    pid = request.form.get('pid')
    if pid and pid.isdigit():
        p = int(pid)
    else:
        abort(422)
    
    post = Post.query.get(pid)
    if not post: abort(404)

    at = Attention.query.filter_by(name_hash=hash_name(u.name), pid=pid).first()

    if not at:
        at = Attention(name_hash=hash_name(u.name), pid=pid, disabled=True)
        db.session.add(at)

    if(at.disabled != (s == '0')):
        at.disabled = (s == '0')
        post.likenum += 1 - 2 * int(s == '0');
        db.session.commit()

    return {'code': 0}

@app.route('/_api/v1/getattention')
def get_attention():
    u = require_token()
    
    ats = Attention.query.filter_by(name_hash=hash_name(u.name), disabled=False)

    posts = [Post.query.get(at.pid) for at in ats.all()]
    print(posts)
    data = [ map_post(post, hash_name(u.name), 10)
            for post in posts[::-1]
                    if post and not post.deleted
        ]

    return {
            'code': 0,
            'count': len(data),
            'data': data
        }


if __name__ == '__main__':
    app.run(debug=True)
