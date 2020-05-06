class KeycloakUserNotFound(Exception):
    def __init__(self, missing_username):
        self.missing_username = missing_username

class KeycloakIdNotFound(Exception):
    def __init__(self, missing_id):
        self.missing_id = missing_id