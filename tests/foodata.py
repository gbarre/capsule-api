available_opt1 = {
    "access_level": "user", # models.RoleEnum.user
    "tag": "Apache",
    "field_name": "vhost.conf",
    "value_type": "file", # models.OptionValueTypeEnum.file
    "field_description": "Apache2 vhost configuration file.",
    "default_value": ""
}

validation_rule1 = {
    "type": "min", # models.ValidationRuleEnum.min
    "arg": "1",
}
validation_rule2 = {
    "type": "max", # models.ValidationRuleEnum.max
    "arg": "42",
}

available_opt2 = {
    "access_level": "user", # models.RoleEnum.user
    "tag": "PHP",
    "field_name": "worker",
    "value_type": "integer", # models.OptionValueTypeEnum.integer
    "field_description": "PHP worker count.",
    "default_value": "6",
    "validation_rules" : [
        validation_rule1,
        validation_rule2
    ]
}

runtime1 = {
    "name": "apache-2.4 php-7.2.x",
    "desc": "Stack web classique Apache 2.4 + PHP 7.2.x",
    "fam": "Apache PHP",
    "runtime_type": "webapp", # models.RuntimeTypeEnum.webapp
    "available_opts": [
        available_opt1,
        available_opt2,
    ],
}

fqdn1 = {
    "name": "main.fqdn.ac-versailles.fr",
    "alias": False
}
fqdn2 = {
    "name": "secondary.fqdn.ac-versailles.fr",
    "alias": True
}

option = {
    "field_name": "worker",
    "tag": "PHP",
    "value": "42"
}

webapp = {
    "env": """
HTTP_PROXY=http://proxy:3128/
HTTPS_PROXY=https://proxy:3128/
""",
    "fqdns": [
        fqdn1,
        fqdn2,
    ],
  "opts" : [
        option,
    ],
    "quota_cpu_max": "2.5",
    "quota_memory_max": "4",
    "quota_volume_size": "20",
    "tls_redirect_https": True,
}

sshkey1 = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCt+vNHscC4LbZY/YQP0hcV4QrwRlhqrcuhAvZZERmp"\
          "NLLOWK4Neaa7ywikVGOOVcY+q3XRHPNZTVkEZhwm0F+/87LJpNhxhZu4BdJ2mfIwx0JS5gRflfeUxxLJ"\
          "AwLXQZpcO7GRdz/w12EgBohHNbxJyKwL7DSFAnaZ08/tlsjoNRlo1k4NHFf5Xf8K3M1ZlXeSxNV9nlpX"\
          "tD6tbVVJn18tDCZgSqH64m1+iVb05sB2htifgkBB+fCElRV/v7Eylc5Zu1EMTlrHmeHB3Yf8DpRMkwYH"\
          "e4j+yDutLvhhZzGmrnNGcD8zZkE1pwKivjwBKee4Bee8NzVR7vMary2GkqY1 john@doe"

sshkey2 = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCqDWN5ay+bKoNg/+DbugWvLjY6q+ODdelRkZTakj7U"\
          "Nq+a40Vm+HHRT2tuoB1NxeR87UieJt9IxWiiTasb/Ss+OgcAn5l8kvQvRQe+dp10qbeQHzkrgjpsFj49"\
          "YDOVKRTrqm5X721TnpqAo2RjqGBeEU+y9REfXPNPMUsni3w/h/BQqJi/e2CRBRdgbi/3bO0Xf0Pt0bc/"\
          "9jjF6vulqzttdbxowbee8bJlPyz/LnNcTGDdmw2PNQFwe0ZuhHsFzSLX4acM3je0+xcdlq0+Gq8nU5jz"\
          "/x0SXuXFz9zFHPO3Ivko1VFdBXaqeb8wOluUjmOxJdDcg3Uqswc5Z08KU+9r jane@doe"

user1 = {
    "name": "toto1",
    "public_keys": [
        sshkey1,
    ],
}

user2 = {
    "name": "tata2",
    "public_keys": [
        sshkey2,
    ],
}

capsule1 = {
    "name": "test-default-capsule",
    "owners": [
        user1["name"],
        user2["name"],
    ],
}
