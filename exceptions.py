import connexion
import werkzeug
import json
from flask import Response


def render_exception(exception):
    if isinstance(exception, connexion.exceptions.ProblemException):
        error = f"{exception.status} {exception.title}"
        error_description = exception.detail
        code = exception.status
    else:
        if not isinstance(exception, werkzeug.exceptions.HTTPException):
            exception = werkzeug.exceptions.InternalServerError()
        error = f"{exception.code} {exception.name}"
        error_description = exception.description
        code = exception.code

    return Response(
        response=json.dumps(
            {'error': error,
             'error_description': error_description}),
        status=code,
        mimetype="application/json")


class KeycloakUserNotFound(Exception):
    def __init__(self, missing_username):
        self.missing_username = missing_username


class KeycloakIdNotFound(Exception):
    def __init__(self, missing_id):
        self.missing_id = missing_id


class ConfigError(Exception):
    pass


class NotRSACertificate(Exception):
    pass


class NotValidPEMFile(Exception):
    pass
