from hole import app
from models import Post, db

with app.app_context():
    for post in Post.query:
        post.n_comments = len([c for c in post.comments if not c.deleted])

    db.session.commit()
