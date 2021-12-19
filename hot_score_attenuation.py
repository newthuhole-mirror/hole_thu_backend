import time
from hole import app
from models import Post, db

with app.app_context():
    for p in Post.query.filter(
        Post.hot_score > 10
    ).all():
        if time.time() - p.timestamp > 60 * 60 * 24 * 3:
            p.hot_score = 10
        else:
            p.hot_score = int(p.hot_score * 0.9)
    db.session.commit()
