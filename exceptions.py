class KeycloakUserNotFound(Exception):
    def __init__(self, missing_username):
        self.missing_username = missing_username