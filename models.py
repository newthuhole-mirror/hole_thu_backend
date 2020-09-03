from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(16))
    token = db.Column(db.String(16), default=None)

    def __repr__(self):
        return f"{self.name}({self.token})"

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name_hash = db.Column(db.String(64))
    content = db.Column(db.String(4096))
    post_type = db.Column(db.String(8))
    cw = db.Column(db.String(32))
    file_url = db.Column(db.String(256))
    likenum = db.Column(db.Integer, default=0)
    timestamp = db.Column(db.Integer)
    deleted = db.Column(db.Boolean, default=False)

    comments = db.relationship('Comment', backref='post', lazy=True)

    def __repr__(self):
        return f"{self.name_hash}:[{self.content}]"

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name_hash = db.Column(db.String(64))
    content = db.Column(db.String(4096))
    timestamp = db.Column(db.Integer)
    deleted = db.Column(db.Boolean, default=False)

    post_id = db.Column(db.Integer, db.ForeignKey('post.id'),
        nullable=False)
    
    def __repr__(self):
        return f"{self.name_hash}:[{self.content}->{self.post_id}]"

class Attention(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name_hash = db.Column(db.String(64))
    pid = db.Column(db.Integer)
    disabled = db.Column(db.Boolean, default=False)
    
