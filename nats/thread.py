import os
import threading
from models import Capsule
from app import nats, db
from sqlalchemy import orm, create_engine

# TODO: Configuration must be unified
session_factory = orm.sessionmaker(bind=create_engine('{driver}://{user}:{passw}@{host}:{port}/{db}'.format(
        driver='mysql+pymysql',
        user='root',
        passw=os.environ.get('MYSQL_ROOT_PASSWORD'),
        host='localhost',
        port=30306,
        db=os.environ.get('MYSQL_DATABASE'),
    )))
session = orm.scoped_session(session_factory)


class NATSListener(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)

        nats.client.subscribe('capsule-api', callback=self.get_capsule)

    @staticmethod
    def get_capsule(msg):
        print(msg)
        print(f'RECEIVED {msg.payload.decode()}')
        capsule = session.query(Capsule).get(msg.payload.decode())
        print(capsule)
        #nats.client.publish('capsule', payload=b'TEST')

    def run(self):
        nats.client.wait()
