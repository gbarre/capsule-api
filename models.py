# TODO: Review
# User table ?

import enum
from datetime import datetime
from config import db, ma
from sqlalchemy.orm import backref
from sqlalchemy.ext.hybrid import hybrid_property
from marshmallow import fields


class RuntimeTypeEnum(enum.Enum):
    webapp = 0
    addon = 1


class RoleEnum(enum.Enum):
    user = 10
    admin = 20
    superadmin = 30


class OptionValueTypeEnum(enum.Enum):
    # FIXME: Decide the types
    integer = 0
    float = 1
    boolean = 2
    string = 3
    file = 4


class ValidationRuleEnum(enum.Enum):
    regex = 0
    gt = 3
    lt = 4
    gte = 5
    lte = 6
    eq = 7
    neq = 8
    format = 9  # check file format


class User(db.Model):
    __tablename__ = "users"
    user_id = db.Column(db.Integer, primary_key=True)
    user_guid = db.Column(db.String, unique=True)  # LDAP nsUniqueId
    public_keys = db.relationship(
        "SSHKey",
        backref="owner",
        cascade="all, delete, delete-orphan",
        single_parent=True,
    )
    role = db.Column(db.Enum(RoleEnum), default=RoleEnum.user, nullable=False)


class Runtime(db.Model):
    __tablename__ = "runtimes"
    runtime_id = db.Column(db.Integer, primary_key=True)
    runtime_guid = db.Column(db.GUID, unique=True)
    name = db.Column(db.String, nullable=False)
    description = db.Column(db.String)
    family = db.Column(db.String)
    type = db.Column(db.Enum(RuntimeTypeEnum), nullable=False)
    webapps = db.relationship(
        "WebApp",
        backref="runtime",
        single_parent=True,
    )
    addons = db.relationship(
        "AddOn",
        backref="runtime",
        single_parent=True,
    )
    available_opts = db.relationship(
        "AvailableOption",
        backref="runtime",
        cascade="all, delete, delete-orphan",
        single_parent=True,
    )
    created_at = db.Column(
        db.DateTime, default=datetime.utcnow
    )
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    @hybrid_property
    def instances(self):
        return self.webapps or self.addons


class AvailableOption(db.Model):
    __tablename__ = "available_options"
    available_option_id = db.Column(db.Integer, primary_key=True)
    available_option_guid = db.Column(db.GUID, unique=True)
    runtime_id = db.Column(db.GUID, db.ForeignKey('runtimes.runtime_guid'))
    access_level = db.Column(
        db.Enum(RoleEnum), default=RoleEnum.superadmin, nullable=False)
    tag = db.Column(db.String, nullable=False)
    name = db.Column(db.String, nullable=False)
    description = db.Column(db.String)
    value_type = db.Column(db.Enum(OptionValueTypeEnum), nullable=False)
    default_value = db.Column(db.String)
    validation_rules = db.relationship(
        "AvailableOptionValidationRule",
        backref="available_option",
        cascade="all, delete, delete-orphan",
        single_parent=True,
    )


class AvailableOptionValidationRule(db.Model):
    __tablename__ = "available_option_validation_rules"
    validation_rule_id = db.Column(db.Integer, primary_key=True)
    validation_rule_guid = db.Column(db.GUID, unique=True)
    available_option_guid = db.Column(db.GUID, db.ForeignKey(
        'available_options.available_option_guid'))
    type = db.Column(db.Enum(ValidationRuleEnum), nullable=False)
    arg = db.Column(db.String, nullable=False)


class AddOn(db.Model):
    __tablename__ = "addons"
    addon_id = db.Column(db.Integer, primary_key=True)
    addon_guid = db.Column(db.GUID, unique=True)
    runtime_guid = db.Column(db.GUID, db.ForeignKey('runtimes.runtime_guid'))
    capsule_guid = db.Column(db.GUID, db.ForeignKey('capsules.capsule_guid'))
    name = db.Column(db.String, nullable=False)
    description = db.Column(db.String)
    uri = db.Column(db.String, nullable=False)
    env = db.Column(db.String)
    opts = db.relationship(
        "Option",
        backref="addon",
        cascade="all, delete, delete-orphan",
        single_parent=True,
    )
    quota_volume_size = db.Column(db.String, nullable=False)
    quota_memory_max = db.Column(db.String, nullable=False)
    quota_cpu_max = db.Column(db.String, nullable=False)
    created_at = db.Column(
        db.DateTime, default=datetime.utcnow
    )
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )


class WebApp(db.Model):
    __tablename__ = "webapps"
    webapp_id = db.Column(db.Integer, primary_key=True)
    webapp_guid = db.Column(db.GUID, unique=True)
    runtime_guid = db.Column(db.GUID, db.ForeignKey('runtimes.runtime_guid'))
    tls_redirect_https = db.Column(db.Boolean, default=True)
    tls_crt = db.Column(db.String)
    tls_key = db.Column(db.String)
    fqns = db.relationship(
        "FQDN",
        backref="webapp",
        cascade="all, delete, delete-orphan",
        single_parent=True,
        order_by="asc(FQDN.alias)",
    )
    env = db.Column(db.String)
    opts = db.relationship(
        "Option",
        backref="webapp",
        cascade="all, delete, delete-orphan",
        single_parent=True,
    )
    quota_volume_size = db.Column(db.String, nullable=False)
    quota_memory_max = db.Column(db.String, nullable=False)
    quota_cpu_max = db.Column(db.String, nullable=False)
    created_at = db.Column(
        db.DateTime, default=datetime.utcnow
    )
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )


class Option(db.Model):
    # TODO: Check that there is not two foreign ref active / @listens_for
    __tablename__ = "options"
    option_id = db.Column(db.Integer, primary_key=True)
    option_guid = db.Column(db.GUID, unique=True)
    webapp_guid = db.Column(db.GUID, db.ForeignKey(
        'webapps.webapp_guid'), nullable=True)
    addon_guid = db.Column(db.GUID, db.ForeignKey(
        'addons.addon_guid'), nullable=True)
    tag = db.Column(db.String)
    field_name = db.Column(db.String)
    value = db.Column(db.String)

    @hybrid_property  # @property compliant with SQLAlchemy
    def instance_id(self):
        return self.webapp_id or self.addon_id


class FQDN(db.Model):
    __tablename__ = "fqdns"
    fqdn_id = db.Column(db.Integer, primary_key=True)
    fqdn_guid = db.Column(db.GUID, unique=True)
    webapp_guid = db.Column(db.GUID, db.ForeignKey('webapps.webapp_guid'))
    name = db.Column(db.String, nullable=False, unique=True)
    alias = db.Column(db.Boolean, nullable=False, default=False)


capsules_users_table = db.Table('capsules_users', db.Base.metadata,
                                db.Column('capsule_guid', db.GUID,
                                          db.ForeignKey('capsules.capsule_guid')),
                                db.Column('user_guid', db.GUID,
                                          db.ForeignKey('users.user_guid')),
                                )

capsules_sshkeys_table = db.Table('capsules_sshkeys', db.Base.metadata,
                                  db.Column('capsule_guid', db.GUID,
                                            db.ForeignKey('capsules.capsule_guid')),
                                  db.Column('sshkey_guid', db.GUID,
                                            db.ForeignKey('sshkeys.sshkey_guid')),
                                  )


# TODO: Discuss SSHKey Management as tables entry and not string ?
class SSHKey(db.Model):
    __tablename__ = "sshkeys"
    sshkey_id = db.Column(db.Integer, primary_key=True)
    sshkey_guid = db.Column(db.GUID, unique=True)
    public_key = db.Column(db.String, nullable=False, unique=True)
    user_guid = db.Column(db.String, db.ForeignKey(
        'users.user_guid'), nullable=True)


class Capsule(db.Model):
    # TODO quota?
    __tablename__ = "capsules"
    capsule_id = db.Column(db.Integer, primary_key=True)
    capsule_guid = db.Column(db.GUID, unique=True)
    name = db.Column(db.String, nullable=False)
    webapp_guid = db.Column(db.GUID, db.ForeignKey(
        'webapps.webapp_guid'), nullable=True)
    webapp = db.relationship(
        "WebApp",
        backref=backref("capsule", uselist=False),
        cascade="all, delete, delete-orphan",
        single_parent=True,
    )
    addons = db.relationship(
        "AddOn",
        backref="capsule",
        cascade="all, delete, delete-orphan",
        single_parent=True,
    )
    authorized_keys = db.relationship(
        "SSHKey",
        secondary=capsules_sshkeys_table,
        backref="capsules",
    )
    owners = db.relationship(
        "User",
        secondary=capsules_users_table,
        backref="capsules",
    )

# FIXME: Check cross references
# TODO: Check required property


class RuntimeSchema(ma.ModelSchema):
    def __init__(self, **kwargs):
        super().__init__(strict=True, **kwargs)

    class Meta:
        model = Runtime
        exclude = ('runtime_id', 'runtime_guid')
        sqla_session = db.session

    id = ma.auto_field('runtime_guid', dump_only=True)
    webapp = fields.Nested('WebAppSchema', default=[], many=True)
    addons = fields.Nested('AddOnSchema', default=[], many=True)
    available_opts = fields.Nested(
        'AvailableOptionSchema', default=[], many=True, exclude=('available_option_id',))
    created_at = ma.auto_field(dump_only=True)
    updated_at = ma.auto_field(dump_only=True)


class AvailableOptionSchema(ma.ModelSchema):
    def __init__(self, **kwargs):
        super().__init__(strict=True, **kwargs)

    class Meta:
        model = AvailableOption
        sqla_session = db.session

    validation_rules = fields.Nested(
        'AvailableOptionValidationRuleSchema', default=[], many=True, exclude=('validation_rule_id',))


class AvailableOptionValidationRuleSchema(ma.ModelSchema):
    def __init__(self, **kwargs):
        super().__init__(strict=True, **kwargs)

    class Meta:
        model = AvailableOptionValidationRule
        sqla_session = db.session


class WebAppSchema(ma.ModelSchema):
    def __init__(self, **kwargs):
        super().__init__(strict=True, **kwargs)

    class Meta:
        model = WebApp
        exclude = ('webapp_id', 'webapp_guid')
        sqla_session = db.session

    id = ma.auto_field('webapp_guid', dump_only=True)
    insecure = fields.Boolean(default=False)
    fqdns = fields.Nested("FQDNSchema", default=[], many=True, only=('name',))
    opts = fields.Nested(
        "OptionSchema",
        default=[],
        many=True,
        only=('tag', 'field_name', 'value'),
    )
    tls_crt = ma.auto_field(load_only=True)
    tls_key = ma.auto_field(load_only=True)
    created_at = ma.auto_field(dump_only=True)
    updated_at = ma.auto_field(dump_only=True)


class AddOnSchema(ma.ModelSchema):
    def __init__(self, **kwargs):
        super().__init__(strict=True, **kwargs)

    class Meta:
        model = AddOn
        exclude = ('addon_id', 'addon_guid')
        sqla_session = db.session

    id = ma.auto_field('addon_guid', dump_only=True)
    uri = ma.auto_field(dump_only=True)
    opts = fields.Nested(
        "OptionSchema",
        default=[],
        many=True,
        only=('tag', 'field_name', 'value'),
    )
    created_at = ma.auto_field(dump_only=True)
    updated_at = ma.auto_field(dump_only=True)


class OptionSchema(ma.ModelSchema):
    def __init__(self, **kwargs):
        super().__init__(strict=True, **kwargs)

    class Meta:
        model = Option
        sqla_session = db.session


class FQDNSchema(ma.ModelSchema):
    def __init__(self, **kwargs):
        super().__init__(strict=True, **kwargs)

    class Meta:
        model = FQDN
        sqla_session = db.session


class SSHKeySchema(ma.ModelSchema):
    def __init__(self, **kwargs):
        super().__init__(strict=True, **kwargs)

    class Meta:
        model = SSHKey
        sqla_session = db.session


class CapsuleSchema(ma.ModelSchema):
    def __init__(self, **kwargs):
        super().__init__(strict=True, **kwargs)

    class Meta:
        model = Capsule
        exclude = ('capsule_id', 'capsule_guid')
        sqla_session = db.session

    id = ma.auto_field('capsule_guid', dump_only=True)
    authorized_keys = fields.Nested(
        "SSHKeySchema", default=[], many=True, only=('public_key'))
    created_at = ma.auto_field(dump_only=True)
    updated_at = ma.auto_field(dump_only=True)
