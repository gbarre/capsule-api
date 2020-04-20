import os
from datetime import datetime
from config import db
from models import *

def init_db():
    # Create the database
    db.create_all()
    db.session.commit()
