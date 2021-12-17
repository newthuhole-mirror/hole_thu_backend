from hole import app
from models import Post, db

with app.app_context():
    for p in Post.query.filter(
        Post.hot_score > 0
    ).all():
        p.hot_score = int(p.hot_score * 0.9)
    db.session.commit()
