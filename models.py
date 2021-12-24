import time
from flask_sqlalchemy import SQLAlchemy
import sqlite3

from config import SEARCH_DB, EXT_SIMPLE_URL
# 搜索用的fts表放到单独的database里，为了不影响flask-migrate和避免死锁

db = SQLAlchemy()

SEARCH_INSERT_SQL = "INSERT INTO search_content VALUES(?, ?, ?);"
SEARCH_QUERY_SQL = "SELECT simple_highlight(search_content, 0, ' **', '** '), target_type, target_id FROM search_content WHERE content MATCH simple_query(?) ORDER BY rank LIMIT ? OFFSET ?;"


class SearchDB:
    def __init__(self):
        self.db = sqlite3.connect(SEARCH_DB)
        self.db.enable_load_extension(True)
        self.db.load_extension(EXT_SIMPLE_URL)
        self.cursor = self.db.cursor()

    def __del__(self):
        if hasattr(self, 'db') and self.db:
            self.db.close()
            del self.db

    def execute(self, sql, *params):
        return self.cursor.execute(sql, params)

    def commit(self):
        self.db.commit()

    def insert(self, *args):
        return self.execute(SEARCH_INSERT_SQL, *args)

    def query(self, *args):
        return self.execute(SEARCH_QUERY_SQL, *args)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(16))
    token = db.Column(db.String(16), default=None)

    def __repr__(self):
        return f"{self.name}({self.token})"


class Post(db.Model):
    __table_args__ = {'sqlite_autoincrement': True}

    id = db.Column(db.Integer, primary_key=True)
    name_hash = db.Column(db.String(64))
    author_title = db.Column(db.String(10))
    content = db.Column(db.String(4096))
    search_text = db.Column(db.String(4096), default='', index=True)
    allow_search = db.Column(db.Boolean, default=False)
    post_type = db.Column(db.String(8))
    cw = db.Column(db.String(32))
    file_url = db.Column(db.String(256))
    likenum = db.Column(db.Integer, default=0)
    n_comments = db.Column(db.Integer, default=0)
    timestamp = db.Column(db.Integer)
    deleted = db.Column(db.Boolean, default=False)
    is_reported = db.Column(db.Boolean, default=False)
    comment_timestamp = db.Column(db.Integer, default=0, index=True)
    hot_score = db.Column(db.Integer, default=0,
                          nullable=False, server_default="0")

    comments = db.relationship('Comment', backref='post', lazy=True)

    def __init__(self, **kwargs):
        super(Post, self).__init__(**kwargs)
        self.timestamp = self.comment_timestamp = int(time.time())

    def __repr__(self):
        return f"{self.name_hash}:[{self.content}]"


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name_hash = db.Column(db.String(64))
    author_title = db.Column(db.String(10))
    content = db.Column(db.String(4096))
    timestamp = db.Column(db.Integer)
    deleted = db.Column(db.Boolean, default=False)

    post_id = db.Column(db.Integer, db.ForeignKey('post.id'),
                        nullable=False)

    @property
    def post(self):
        return Post.query.get(self.post_id)

    def __init__(self, **kwargs):
        super(Comment, self).__init__(**kwargs)
        self.timestamp = int(time.time())

    def __repr__(self):
        return f"{self.name_hash}:[{self.content}->{self.post_id}]"


class Attention(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name_hash = db.Column(db.String(64))
    pid = db.Column(db.Integer)
    disabled = db.Column(db.Boolean, default=False)


class TagRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tag = db.Column(db.String(32))
    pid = db.Column(db.Integer)


class Syslog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    log_type = db.Column(db.String(16))
    log_detail = db.Column(db.String(128))
    name_hash = db.Column(db.String(64))
    timestamp = db.Column(db.Integer)

    def __init__(self, **kwargs):
        super(Syslog, self).__init__(**kwargs)
        self.timestamp = int(time.time())
