from hole import app
from models import SearchDB, Post, db

search_db = SearchDB()
search_db.execute("DROP TABLE IF EXISTS search_content;")
search_db.execute("CREATE VIRTUAL TABLE search_content "
                  "USING fts5(content, target_type UNINDEXED, target_id UNINDEXED, tokenize = 'simple');")

with app.app_context():
    for post in Post.query.filter_by(deleted=False):
        if post.search_text:
            search_db.insert(post.search_text, 'post', post.id)
            post.allow_search = True
            for comment in post.comments:
                if not comment.deleted:
                    search_db.insert(comment.content, 'comment', comment.id)
        else:
            post.allow_search = False

    search_db.commit()
    del search_db
    db.session.commit()
