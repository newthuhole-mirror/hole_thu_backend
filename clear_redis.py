# 每次重置时执行
from utils import rds, RDS_KEY_TITLE, RDS_KEY_BLOCKED_COUNT

rds.delete(RDS_KEY_BLOCKED_COUNT)
rds.delete(RDS_KEY_TITLE)
