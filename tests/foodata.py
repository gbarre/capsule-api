from models import *


class DBFooData:

    def __init__(self, db):

        self.available_opt1 = AvailableOption(
            access_level=RoleEnum.user,
            tag="Apache",
            field_name="vhost.conf",
            value_type=OptionValueTypeEnum.file,
            field_description="Apache2 vhost configuration file.",
            default_value="",
        )

        self.validation_rule1 = AvailableOptionValidationRule(
            type=ValidationRuleEnum.min,
            arg="1",
        )
        self.validation_rule2 = AvailableOptionValidationRule(
            type=ValidationRuleEnum.max,
            arg="42",
        )

        self.available_opt2 = AvailableOption(
            access_level=RoleEnum.user,
            tag="PHP",
            field_name="worker",
            value_type=OptionValueTypeEnum.integer,
            field_description="PHP worker count.",
            default_value="6",
            validation_rules=[
                self.validation_rule1,
                self.validation_rule2,
            ],
        )

        self.runtime1 = Runtime(
            name="apache-2.4 php-7.2.x",
            desc="Stack web classique Apache 2.4 + PHP 7.2.x",
            fam="Apache PHP",
            runtime_type=RuntimeTypeEnum.webapp,
            available_opts=[
                self.available_opt1,
                self.available_opt2,
            ],
        )

        self.runtime2 = Runtime(
            name="MariaDB 10.1",
            desc="SQL server",
            fam="SQL",
            runtime_type=RuntimeTypeEnum.addon,
        )

        self.fqdn1 = FQDN(
            name="main.fqdn.ac-versailles.fr",
            alias=False,
        )
        self.fqdn2 = FQDN(
            name="secondary.fqdn.ac-versailles.fr",
            alias=True,
        )

        self.option1 = Option(
            field_name="worker",
            tag="PHP",
            value="42",
        )

        self.webapp1 = WebApp(
            env='{"HTTP_PROXY": "http://proxy:3128/", "HTTPS_PROXY": "https://proxy:3128/"}',
            fqdns=[
                self.fqdn1,
                self.fqdn2,
            ],
            opts=[
                self.option1,
            ],
            quota_cpu_max="2.5",
            quota_memory_max="4",
            quota_volume_size="20",
            tls_redirect_https=True,
            # "runtime_id": "b5ce1c27-b2bb-4eaf-8d29-c8dee632df67",
            runtime=self.runtime1,
        )

        self.addon1 = AddOn(
            description="Service de base de données pour ma capsule",
            env='{"HTTP_PROXY": "http://proxy:3128/", "HTTPS_PROXY": "https://proxy:3128/"}',
            name="MySQL-1",
            opts=[],
            # "runtime_id": "10f6e1d7-2976-43e4-a4a5-bab833cb3241",
            runtime=self.runtime2,
        )

        self.sshkey1 = SSHKey(
            public_key="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCt+vNHscC4LbZY/YQP0hcV4QrwRlhqrcuhAvZZERmp"\
                "NLLOWK4Neaa7ywikVGOOVcY+q3XRHPNZTVkEZhwm0F+/87LJpNhxhZu4BdJ2mfIwx0JS5gRflfeUxxLJ"\
                "AwLXQZpcO7GRdz/w12EgBohHNbxJyKwL7DSFAnaZ08/tlsjoNRlo1k4NHFf5Xf8K3M1ZlXeSxNV9nlpX"\
                "tD6tbVVJn18tDCZgSqH64m1+iVb05sB2htifgkBB+fCElRV/v7Eylc5Zu1EMTlrHmeHB3Yf8DpRMkwYH"\
                "e4j+yDutLvhhZzGmrnNGcD8zZkE1pwKivjwBKee4Bee8NzVR7vMary2GkqY1 john@doe",
        )

        self.sshkey2 = SSHKey(
            public_key="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCqDWN5ay+bKoNg/+DbugWvLjY6q+ODdelRkZTakj7U"\
                "Nq+a40Vm+HHRT2tuoB1NxeR87UieJt9IxWiiTasb/Ss+OgcAn5l8kvQvRQe+dp10qbeQHzkrgjpsFj49"\
                "YDOVKRTrqm5X721TnpqAo2RjqGBeEU+y9REfXPNPMUsni3w/h/BQqJi/e2CRBRdgbi/3bO0Xf0Pt0bc/"\
                "9jjF6vulqzttdbxowbee8bJlPyz/LnNcTGDdmw2PNQFwe0ZuhHsFzSLX4acM3je0+xcdlq0+Gq8nU5jz"\
                "/x0SXuXFz9zFHPO3Ivko1VFdBXaqeb8wOluUjmOxJdDcg3Uqswc5Z08KU+9r jane@doe",
        )

        # Users.
        self.admin_user = User(name="admin_user", role=RoleEnum.admin)
        self.superadmin_user = User(name="superadmin_user", role=RoleEnum.superadmin)
        self.fake_user = User(name="fake_user", role=RoleEnum.user)
        self.user1 = User(name="user1", role=RoleEnum.user)
        self.user2 = User(name="user2", role=RoleEnum.user)
        self.user3 = User(name="user3", role=RoleEnum.user)

        self.user1.public_keys.append(self.sshkey1)
        self.user2.public_keys.append(self.sshkey2)

        self.capsule1 = Capsule(
            name="test-default-capsule",
            owners=[
                self.user1,
                self.user2,
            ],
            webapp = self.webapp1,
            addons = [
                self.addon1,
            ]
        )

        array_obj = []

        for name, value in vars(self).items():
            array_obj.append(value)

        db.session.add_all(array_obj)
        db.session.commit()

        # Just handy in test functions.
        self.users = [
            self.admin_user,
            self.superadmin_user,
            self.fake_user,
            self.user1,
            self.user2,
            self.user3,
        ]
