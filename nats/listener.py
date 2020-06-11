import os
import json
import threading
from models import capsule_verbose_schema
from models import WebApp, webapp_schema
from models import AddOn, addon_schema
from sqlalchemy import orm, create_engine
from app import nats
from json.decoder import JSONDecodeError
from ast import literal_eval


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
        json_msg = msg.json

        is_json_valid, error_msg = msg.is_json_valid()

        if not is_json_valid:
            nats.publish_error(
                msg.subject,
                'invalid',
                error_msg)
            return

        data_json = json_msg['data']
        query_id = data_json['id']

        if "capsule.webapp" in msg.subject:
            try:
                # get capsule from the webapp id
                webapp = session.query(WebApp).get(query_id)
                webapp_data = webapp_schema.dump(webapp).data
                webapp_data["env"] = literal_eval(webapp_data["env"])

                capsule = webapp.capsule
                capsule_data = capsule_verbose_schema.dump(capsule).data

                # build data to publish
                data = {
                    "authorized_keys": [],  # to build
                    "capsule-id": str(capsule.id),
                    "name": capsule.name,
                    "owners": [],  # to build
                    "webapp": webapp_data,
                }
            except Exception:
                nats.publish_error(
                    origin_subject,
                    'not found',
                    f"webapp '{query_id}' has not been found.")
                return

            # continue building data
            for sshkey in capsule_data['authorized_keys']:
                data['authorized_keys'].append(sshkey['public_key'])

            for owner in capsule_data['owners']:
                for sshkey in owner['public_keys']:
                    data['authorized_keys'].append(sshkey['public_key'])
                data['owners'].append(owner['name'])

            # publish data
            nats.publish(origin_subject, data)

        elif "capsule.addon" in msg.subject:
            try:
                # get capsule from the addon id
                addon = session.query(AddOn).get(query_id)
                addon_data = addon_schema.dump(addon).data
                addon_data["env"] = literal_eval(addon_data["env"])
                addon_data.pop('capsule_id')

                capsule = addon.capsule
                capsule_data = capsule_verbose_schema.dump(capsule).data

                # build data to publish
                data = {
                    "capsule-id": str(capsule.id),
                    "name": capsule.name,
                    "owners": [],  # to build
                    "addon": addon_data,
                }
            except Exception:
                nats.publish_error(
                    origin_subject,
                    'not found',
                    f"addon '{query_id}' has not been found.")
                return

            for owner in capsule_data['owners']:
                data['owners'].append(owner['name'])

            # publish data
            nats.publish(origin_subject, data)
        else:
            nats.publish_error(
                origin_subject,
                'invalid',
                'nothing to be done.'
            )

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
        if not(isinstance(self.json['data'], dict)
           and 'id' in self.json['data']):
            return (False, 'Data value must be an object '
                           'with the key "id"')
        return (True, None)


def create_nats_listener(app):
    nats.init_app(app)
    nats_listener = NATSListener()
    return nats_listener
