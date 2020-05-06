available_opt1 = {
    "access_level": "user", # models.RoleEnum.user
    "tag": "Apache",
    "name": "vhost.conf",
    "value_type": "file", # models.OptionValueTypeEnum.file
    "description": "Apache2 vhost configuration file.",
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
    "name": "worker",
    "value_type": "integer", # models.OptionValueTypeEnum.integer
    "description": "PHP worker count.",
    "default_value": "6",
    "validation_rules" : {
        validation_rule1["type"]: validation_rule1["arg"],
        validation_rule2["type"]: validation_rule2["arg"],
    }
}

runtime1 = {
    "name": "apache-2.4 php-7.2.x",
    "description": "Stack web classique Apache 2.4 + PHP 7.2.x",
    "family": "Apache PHP",
    "type": "webapp", # models.RuntimeTypeEnum.webapp
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

capsule1 = {
    "name": "Test Default Capsule",
    "owners": [
        "toto1",
        "tata2",
    ],
}