import re
import random
import string

from flask import Flask, request, abort, redirect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_migrate import Migrate
from sqlalchemy.sql.expression import func

from mastodon import Mastodon
from models import db, User, Post, Comment, Attention, TagRecord, Syslog
from utils import get_current_username, map_post, map_comment, map_syslog, check_attention, hash_name, look, get_num, tmp_token, is_admin, check_can_del, rds, RDS_KEY_POLL_OPTS, RDS_KEY_POLL_VOTES, gen_poll_dict, name_with_tmp_limit, RDS_KEY_BLOCK_SET, RDS_KEY_BLOCKED_COUNT, RDS_KEY_DANGEROUS_USERS, RDS_KEY_TITLE

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///hole.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JSON_AS_ASCII'] = False
app.config['SALT'] = ''.join(random.choices(
    string.ascii_letters + string.digits, k=32
))
app.config.from_pyfile('config.py')

db.init_app(app)
migrate = Migrate(app, db)

CS_LOGIN_URL = Mastodon(api_base_url=app.config['MASTODON_URL']) \
    .auth_request_url(
    client_id=app.config['CLIENT_ID'],
    redirect_uris=app.config['REDIRECT_URI'],
    scopes=['read:accounts']
)

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["1000 / hour"],
)

PER_PAGE = 50
DANGEROUS_USER_THRESHOLD = 10


class APIError(Exception):
    msg = '未知错误'

    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return str(self.msg)


@app.errorhandler(APIError)
def handle_api_error(e):
    return {'code': 1, 'msg': e.msg}


@app.route('/_login')
@limiter.limit("5 / minute, 50 / hour")
def login():
    provider = request.args.get('p')
    if provider == 'cs':
        return redirect(CS_LOGIN_URL)

    abort(401)


@app.route('/_auth')
@limiter.limit("5 / minute")
def auth():
    # Currently, only for closed.social
    code = request.args.get('code')
    client = Mastodon(
        client_id=app.config['CLIENT_ID'],
        client_secret=app.config['CLIENT_SECRET'],
        api_base_url=app.config['MASTODON_URL']
    )
    client.log_in(
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

    if not v or False:  # TODO: reset token
        u.token = ''.join(
            random.choices(
                string.ascii_letters +
                string.digits,
                k=16))
        db.session.commit()

    return redirect('/?token=%s' % u.token)


@app.route('/_api/v1/getlist')
def get_list():
    username = get_current_username()

    p = request.args.get('p', type=int, default=1)
    order_mode = request.args.get('order_mode', type=int, default=0)
    if request.args.get('by_c'):
        order_mode = 1  # 兼容旧版前端
    if order_mode == 3:
        p = 1

    query = Post.query.filter_by(deleted=False)
    if 'no_cw' in request.args:
        query = query.filter_by(cw=None)
    if order_mode == 2:
        query = query.filter(
            Post.hot_score != -1
        ).filter_by(is_reported=False)

    order = {
        1: Post.comment_timestamp.desc(),  # 最近评论
        2: Post.hot_score.desc(),  # 热门
        3: func.random()  # 随机
    }.get(order_mode, Post.id.desc())  # 最新

    posts = query.order_by(order).paginate(p, PER_PAGE)

    data = list(map(map_post, posts.items, [username] * len(posts.items)))

    return {
        'code': 0,
        'tmp_token': tmp_token(),
        'custom_title': rds.hget(RDS_KEY_TITLE, hash_name(username)),
        'count': len(data),
        'data': data
    }


@app.route('/_api/v1/getone')
def get_one():
    username = get_current_username()

    pid = request.args.get('pid', type=int)

    post = Post.query.get_or_404(pid)
    if post.deleted or post.is_reported and not (
        check_can_del(username, post.name_hash)
    ):
        abort(451)

    data = map_post(post, username)

    return {
        'code': 0,
        'data': data
    }


@app.route('/_api/v1/getmulti')
def get_multi():
    username = get_current_username()
    pids = request.args.getlist('pids')
    pids = pids[:500] or [0]

    posts = Post.query.filter(
        Post.id.in_(pids)
    ).filter_by(
        deleted=False
    ).order_by(
        Post.id.desc()
    ).all()

    data = [map_post(post, username) for post in posts]

    return {
        'code': 0,
        'data': data
    }


@app.route('/_api/v1/search')
def search():
    username = get_current_username()

    page = request.args.get('page', type=int, default=1)
    pagesize = min(request.args.get('pagesize', type=int, default=200), 200)
    keywords = request.args.get('keywords')
    if not keywords:
        abort(422)

    tag_pids = TagRecord.query.with_entities(
        TagRecord.pid
    ).filter_by(
        tag=keywords
    ).all()

    tag_pids = [
        tag_pid for tag_pid, in tag_pids] or [0]  # sql not allowed empty in

    posts = Post.query.filter(
        Post.search_text.like("%{}%".format(keywords))
    ).filter(
        Post.id.notin_(tag_pids)
    ).filter_by(
        deleted=False, is_reported=False
    ).order_by(
        Post.id.desc()
    ).limit(pagesize).offset((page - 1) * pagesize).all()

    if page == 1:
        posts = Post.query.filter(
            Post.id.in_(tag_pids)
        ).filter_by(
            deleted=False, is_reported=False
        ).order_by(
            Post.id.desc()
        ).all() + posts

    data = [
        map_post(post, username)
        for post in posts
    ]

    return {
        'code': 0,
        'count': len(data),
        'data': data
    }


@app.route('/_api/v1/dopost', methods=['POST'])
@limiter.limit("50 / hour; 1 / 3 second")
def do_post():
    username = get_current_username()

    allow_search = request.form.get('allow_search')
    content = request.form.get('text', '').strip()
    content = ('[tmp]\n' if username[:4] == 'tmp_' else '') + content
    post_type = request.form.get('type')
    cw = request.form.get('cw', '').strip()
    poll_options = request.form.getlist('poll_options')
    use_title = request.form.get('use_title')

    if not content or len(content) > 4096 or len(cw) > 32:
        raise APIError('无内容或超长')

    search_text = content.replace(
        '\n', '') if allow_search else ''

    if poll_options and poll_options[0]:
        if len(poll_options) != len(set(poll_options)):
            raise APIError('有重复的投票选项')
        if len(poll_options) > 8:
            raise APIError('选项过多')
        if max(map(len, poll_options)) > 32:
            raise APIError('选项过长')

    name_hash = hash_name(username)
    p = Post(
        name_hash=name_hash,
        author_title=rds.hget(RDS_KEY_TITLE, name_hash) if use_title else None,
        content=content,
        search_text=search_text,
        post_type=post_type,
        cw=cw or None,
        likenum=1,
        comments=[]
    )

    db.session.add(p)
    db.session.commit()

    tags = re.findall('(^|\\s)#([^#\\s]{1,32})', content)
    for t in tags:
        tag = t[1]
        if not re.match('\\d+', tag):
            db.session.add(TagRecord(tag=tag, pid=p.id))

    db.session.add(Attention(name_hash=hash_name(username), pid=p.id))
    db.session.commit()

    rds.delete(RDS_KEY_POLL_OPTS % p.id)  # 由于历史原因，现在的数据库里发布后删再发布可能导致id重复
    if poll_options and poll_options[0]:
        rds.rpush(RDS_KEY_POLL_OPTS % p.id, *poll_options)

    return {
        'code': 0,
        'date': p.id
    }


@app.route('/_api/v1/editcw', methods=['POST'])
@limiter.limit("50 / hour; 1 / 2 second")
def edit_cw():
    username = get_current_username()

    cw = request.form.get('cw')
    pid = get_num(request.form.get('pid'))

    cw = cw.strip() if cw else None
    if cw and len(cw) > 32:
        abort(422)

    post = Post.query.get_or_404(pid)

    if not check_can_del(username, post.name_hash):
        abort(403)

    post.cw = cw
    db.session.commit()

    return {'code': 0}


@app.route('/_api/v1/getcomment')
def get_comment():
    username = get_current_username()

    pid = get_num(request.args.get('pid'))

    post = Post.query.get_or_404(pid)
    if post.deleted and not check_can_del(username, post.name_hash):
        abort(451)

    data = map_comment(post, username)

    return {
        'code': 0,
        'attention': check_attention(username, pid),
        'likenum': post.likenum,
        'data': data
    }


@app.route('/_api/v1/docomment', methods=['POST'])
@limiter.limit("50 / hour; 1 / 3 second")
def do_comment():
    username = get_current_username()

    pid = get_num(request.form.get('pid'))

    post = Post.query.get(pid)
    if not post:
        abort(404)
    if post.deleted and not check_can_del(username, post.name_hash):
        abort(451)

    content = request.form.get('text', '').strip()
    if username.startswith('tmp_'):
        content = '[tmp]\n' + content
    if not content or len(content) > 4096:
        abort(422)

    use_title = request.form.get('use_title')

    name_hash = hash_name(username)
    c = Comment(
        name_hash=name_hash,
        author_title=rds.hget(RDS_KEY_TITLE, name_hash) if use_title else None,
        content=content,
    )
    post.comments.append(c)
    post.comment_timestamp = c.timestamp

    if post.hot_score != -1:
        post.hot_score += 1

    at = Attention.query.filter_by(
        name_hash=hash_name(username), pid=pid
    ).first()

    if not at:
        at = Attention(name_hash=hash_name(username), pid=pid, disabled=False)
        db.session.add(at)
        post.likenum += 1
        if post.hot_score != -1:
            post.hot_score += 2
    else:
        if at.disabled:
            post.likenum += 1
            at.disabled = False

    db.session.commit()

    return {
        'code': 0,
        'data': pid
    }


@app.route('/_api/v1/attention', methods=['POST'])
@limiter.limit("200 / hour; 1 / second")
def attention():
    username = get_current_username()
    if username[:4] == 'tmp_':
        abort(403)

    s = request.form.get('switch', type=int)
    if s not in [0, 1]:
        abort(422)

    pid = request.form.get('pid', type=int)

    post = Post.query.get_or_404(pid)

    at = Attention.query.filter_by(
        name_hash=hash_name(username), pid=pid
    ).first()

    if not at:
        at = Attention(name_hash=hash_name(username), pid=pid, disabled=True)
        db.session.add(at)
        if post.hot_score != -1:
            post.hot_score += 2

    if at.disabled == bool(s):
        at.disabled = not bool(s)
        post.likenum += 2 * s - 1

    if is_admin(username) and s:
        post.is_reported = False

    db.session.commit()

    return {
        'code': 0,
        'likenum': post.likenum,
        'attention': bool(s)
    }


@app.route('/_api/v1/getattention')
def get_attention():
    username = get_current_username()

    ats = Attention.query.with_entities(
        Attention.pid
    ).filter_by(
        name_hash=hash_name(username), disabled=False
    ).all()

    pids = [pid for pid, in ats] or [0]  # sql not allow empty in
    posts = Post.query.filter(
        Post.id.in_(pids)
    ).filter_by(
        deleted=False
    ).order_by(Post.id.desc()).all()

    data = [
        map_post(post, username, 10)
        for post in posts
    ]

    return {
        'code': 0,
        'count': len(data),
        'data': data
    }


@app.route('/_api/v1/delete', methods=['POST'])
@limiter.limit("50 / hour; 1 / 3 second")
def delete():
    username = get_current_username()

    obj_type = request.form.get('type')
    obj_id = get_num(request.form.get('id'))
    note = request.form.get('note', '')

    if note and len(note) > 100:
        abort(422)

    obj = None
    if obj_type == 'pid':
        obj = Post.query.get(obj_id)
    elif obj_type == 'cid':
        obj = Comment.query.get(obj_id)
    if not obj:
        abort(404)

    if obj.name_hash == hash_name(username):
        if obj_type == 'pid':
            if len(obj.comments):
                abort(403)
            Attention.query.filter_by(pid=obj.id).delete()
            TagRecord.query.filter_by(pid=obj.id).delete()
            db.session.delete(obj)
        else:
            obj.deleted = True
    elif username in app.config.get('ADMINS'):
        obj.deleted = True
        db.session.add(Syslog(
            log_type='ADMIN DELETE',
            log_detail=f"{obj_type}={obj_id}\n{note}",
            name_hash=hash_name(username)
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
    username = get_current_username()

    ss = Syslog.query.order_by(db.desc('timestamp')).limit(100).all()

    return {
        'start_time': app.config['START_TIME'],
        'salt': look(app.config['SALT']),
        'tmp_token': tmp_token(),
        'custom_title': rds.hget(RDS_KEY_TITLE, hash_name(username)),
        'data': [map_syslog(s, username) for s in ss]
    }


@app.route('/_api/v1/report', methods=['POST'])
@limiter.limit("10 / hour; 1 / 3 second")
def report():
    username = get_current_username()
    pid = get_num(request.form.get('pid'))
    reason = request.form.get('reason', '')

    db.session.add(Syslog(
        log_type='REPORT',
        log_detail=f"pid={pid}\n{reason}",
        name_hash=hash_name(username)
    ))

    post = Post.query.get(pid)
    if post:
        post.is_reported = True

    db.session.commit()

    return {'code': 0}


@app.route('/_api/v1/update_score', methods=['POST'])
def edit_hot_score():
    username = get_current_username()
    if not is_admin(username):
        abort(403)

    pid = request.form.get('pid', type=int)
    score = request.form.get('score', type=int)

    post = Post.query.get_or_404(pid)
    post.hot_score = score
    db.session.commit()

    return {'code': 0}


@app.route('/_api/v1/vote', methods=['POST'])
@limiter.limit("100 / hour; 1 / 2 second")
def add_vote():
    username = get_current_username()
    username = name_with_tmp_limit(username)

    pid = request.form.get('pid', type=int)
    vote = request.form.get('vote')

    if not rds.exists(RDS_KEY_POLL_OPTS % pid):
        abort(404)

    opts = rds.lrange(RDS_KEY_POLL_OPTS % pid, 0, -1)
    for idx, opt in enumerate(opts):
        if rds.sismember(RDS_KEY_POLL_VOTES % (pid, idx), hash_name(username)):
            raise APIError('已经投过票了')
    if vote not in opts:
        raise APIError('无效的选项')

    rds.sadd(RDS_KEY_POLL_VOTES % (pid, opts.index(vote)), hash_name(username))

    return {
        'code': 0,
        'data': gen_poll_dict(pid, username)
    }


@app.route('/_api/v1/block', methods=['POST'])
@limiter.limit("15 / hour; 1 / 2 second")
def block_user_by_target():
    username = get_current_username()
    target_type = request.form.get('type')
    target_id = request.form.get('id', type=int)

    if username.startswith('tmp_'):
        raise APIError('临时用户无法拉黑')

    if target_type == 'post':
        target = Post.query.get_or_404(target_id)
    elif target_type == 'comment':
        target = Comment.query.get_or_404(target_id)
    else:
        raise APIError('无效的type')

    if hash_name(username) == target.name_hash:
        raise APIError('不可拉黑自己')

    if is_admin(username):
        rds.sadd(RDS_KEY_DANGEROUS_USERS, target.name_hash)
        curr_cnt = rds.hget(RDS_KEY_BLOCKED_COUNT, target.name_hash)
    else:
        if rds.sismember(RDS_KEY_BLOCK_SET % username, target.name_hash):
            raise APIError('已经拉黑了')
        rds.sadd(RDS_KEY_BLOCK_SET % username, target.name_hash)
        curr_cnt = rds.hincrby(RDS_KEY_BLOCKED_COUNT, target.name_hash, 1)
        if curr_cnt >= DANGEROUS_USER_THRESHOLD:
            rds.sadd(RDS_KEY_DANGEROUS_USERS, target.name_hash)

    return {
        'code': 0,
        'data': {
            'curr': curr_cnt,
            'threshold': DANGEROUS_USER_THRESHOLD
        }
    }


@app.route('/_api/v1/title', methods=['POST'])
@limiter.limit("10 / hour; 1 / 2 second")
def set_title():
    username = get_current_username()

    title = request.form.get('title')
    if not title:
        rds.hdel(RDS_KEY_TITLE, hash_name(username))
    else:
        if len(title) > 10:
            raise APIError('自定义头衔太长')
        if title in rds.hvals(RDS_KEY_TITLE):  # 如果未来量大还是另外用个set维护
            raise APIError('已经被使用了')
        rds.hset(RDS_KEY_TITLE, hash_name(username), title)

    return {'code': 0}


if __name__ == '__main__':
    app.run(debug=True)
