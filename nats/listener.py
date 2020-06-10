import os
import json
import threading
from models import Capsule
from models import WebApp
from models import capsule_output_schema
from models import webapp_schema
from sqlalchemy import orm, create_engine
from app import nats
from json.decoder import JSONDecodeError


# TODO: Configuration must be unified
session_factory = orm.sessionmaker(
    bind=create_engine('{driver}://{user}:{passw}@{host}:{port}/{db}'.format(
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

        msg = NATSDriverMsg(msg)

        # TODO: implements nats listening protocol
        origin_subject = msg.subject
        #payload = json.loads(msg.payload)
        json_msg = msg.json

        is_json_valid, error_msg = msg.is_json_valid()

        if not is_json_valid:
            nats.publish_error(
                msg.subject,
                'invalid',
                error_msg)
            return

        # if 'state' not in json_msg:
        #     nats.publish_error(origin_subject, 'invalid', 'state is missing.')
        #     return

        # reqtype, obj = json_msg['state'].split(':', 1)
        # if reqtype == 'request':
        #     if 'id' not in json_msg:
        #         nats.publish_error(origin_subject, 'invalid', 'id is missing.')
        #         return

        #     id = json_msg['id']
        #     try:
        #         if obj == 'capsule':
        #             capsule = session.query(Capsule).get(id)
        #             capsule_data = capsule_output_schema.dump(capsule).data
        #             nats.publish(origin_subject, capsule_data)
        #             return
        #         elif obj == 'webapp':
        #             webapp = session.query(WebApp).get(id)
        #             webapp_data = webapp_schema.dump(webapp).data
        #             nats.publish(origin_subject, webapp_data)
        #             return
        #     except Exception:
        #         nats.publish_error(
        #             origin_subject,
        #             'not found',
        #             f'{obj} {id} has not been found.')
        #         return

        nats.publish_error(origin_subject, 'invalid', 'nothing to be done.')

    def run(self):
        nats.logger.info('NATS listener waiting for incoming messages.')
        nats.client.wait()


class NATSDriverMsg:

    required_fields = [
        'from',
        'to',
        'message',
        'data',
        'timestamp',
        'signature'
    ]

    def __init__(self, nats_msg):
        self.subject = nats_msg.subject
        self.payload = nats_msg.payload
        try:
            self.json = json.loads(self.payload)
        except JSONDecodeError:
            self.json = None

    def is_json_valid(self):
        if self.json is None:
            return (False, 'Invalid JSON structure')
        if not isinstance(self.json, dict):
            return (False, 'JSON must be an object')
        for field in __class__.required_fields:
            if field not in self.json:
                return (False, f'Key "{field}" is required in JSON')
        if not(isinstance(self.json['data'], dict) \
           and 'capsule-id' in self.json['data']):
            return (False, 'Data value must be an object '\
                            'with the key "capsule-id"')
        return (True, None)

def create_nats_listener(app):
    nats.init_app(app)
    nats_listener = NATSListener()
    return nats_listener
