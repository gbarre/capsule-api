import os
from datetime import datetime
from config import db
from models import *

# Delete database file if it exists currently
if os.path.exists("capsule.db"):
    os.remove("capsule.db")

# Create the database
db.create_all()
db.session.commit()
