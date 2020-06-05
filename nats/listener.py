import os
import json
import threading
import logging
import sqlalchemy
from models import Capsule
from models import WebApp
from models import capsule_output_schema
from models import webapp_schema
from sqlalchemy import orm, create_engine
from app import nats


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
        nats.subscribe(nats.SUBJECT, callback=self.listen)
        nats.logger.info('NATS listener initialized.')

    @staticmethod
    def listen(msg):
        # TODO: implements nats listening protocol
        origin_subject = msg.subject
        payload = json.loads(msg.payload)

        if 'state' not in payload:
            nats.publish_error(origin_subject, 'invalid', 'state is missing.')
            return

        reqtype, obj = payload['state'].split(':', 1)
        if reqtype == 'request':
            if 'id' not in payload:
                nats.publish_error(origin_subject, 'invalid', 'id is missing.')
                return

            id = payload['id']
            try:
                if obj == 'capsule':
                    capsule = session.query(Capsule).get(id)
                    capsule_data = capsule_output_schema.dump(capsule).data
                    nats.publish(origin_subject, capsule_data)
                    return
                elif obj == 'webapp':
                    webapp = session.query(WebApp).get(id)
                    webapp_data = webapp_schema.dump(webapp).data
                    nats.publish(origin_subject, webapp_data)
                    return
            except:
                nats.publish_error(origin_subject, 'not found', f'{obj} {id} has not been found.')
                return
        
        nats.publish_error(origin_subject, 'invalid', 'nothing to be done.')

    def run(self):
        nats.logger.info('NATS listener waiting for incoming messages.')
        nats.client.wait()


def create_nats_listener(app):
    nats.init_app(app)
    nats_listener = NATSListener()
    return nats_listener