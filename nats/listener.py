import os
import json
import threading
import logging
from models import Capsule
from models import capsule_output_schema
from sqlalchemy import orm, create_engine
from app import nats
from nats import logger


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
        # TODO: make subscriptions
        nats.subscribe('capsule-api', callback=self.get_capsule)
        logger.info('NATS listener initialized.')

    @staticmethod
    def get_capsule(msg):
        print(msg)
        print(f'RECEIVED {msg.payload.decode()}')

        capsule = session.query(Capsule).get(msg.payload.decode())
        # ==> Capsule.query.get(msg.payload.decode())

        print(capsule)

        capsule_data = capsule_output_schema.dump(capsule).data
        nats.publish_capsule(capsule_data)

    def run(self):
        logger.info('NATS listener waiting for incoming messages.')
        nats.client.wait()


def create_nats_listener(app):
    nats.init_app(app)
    nats_listener = NATSListener()
    return nats_listener