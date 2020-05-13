# TODO: Quid de savoir la fin de pagination ?

import enum
import uuid
from datetime import datetime
from app import db, ma
from marshmallow import fields
from sqlalchemy.orm import backref
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.types import TypeDecorator, CHAR
from sqlalchemy.dialects.postgresql import UUID


class GUID(TypeDecorator):
    """Platform-independent GUID type.

    Uses PostgreSQL's UUID type, otherwise uses
    CHAR(32), storing as stringified hex values.

    """
    impl = CHAR

    def load_dialect_impl(self, dialect):
        if dialect.name == 'postgresql':
            return dialect.type_descriptor(UUID())
        else:
            return dialect.type_descriptor(CHAR(32))

    def process_bind_param(self, value, dialect):
        if value is None:
            return value
        elif dialect.name == 'postgresql':
            return str(value)
        else:
            if not isinstance(value, uuid.UUID):
                return "%.32x" % uuid.UUID(value).int
            else:
                # hexstring
                return "%.32x" % value.int

    def process_result_value(self, value, dialect):
        if value is None:
            return value
        else:
            if not isinstance(value, uuid.UUID):
                value = uuid.UUID(value)
            return value


class RuntimeTypeEnum(str, enum.Enum):
    webapp = "webapp"
    addon = "addon"


class RoleEnum(str, enum.Enum):

    user = "user"
    admin = "admin"
    superadmin = "superadmin"

    def getpower(self):
        if self == __class__.user:
            return 10
        if self == __class__.admin:
            return 20
        if self == __class__.superadmin:
            return 42

    def __ge__(self, other):
        if self.__class__ is other.__class__:
            return self.getpower() >= other.getpower()
        return NotImplemented

    def __gt__(self, other):
        if self.__class__ is other.__class__:
            return self.getpower() > other.getpower()
        return NotImplemented

    def __le__(self, other):
        if self.__class__ is other.__class__:
            return self.getpower() <= other.getpower()
        return NotImplemented

    def __lt__(self, other):
        if self.__class__ is other.__class__:
            return self.getpower() < other.getpower()
        return NotImplemented


class OptionValueTypeEnum(str, enum.Enum):
    # FIXME: Decide the types
    integer = "integer"
    float = "float"
    boolean = "bloolean"
    string = "string"
    file = "file"


class ValidationRuleEnum(str, enum.Enum):
    regex = "regex"
    min = "min"
    max = "max"
    eq = "eq"
    neq = "neq"
    format = "format"  # check file format


class User(db.Model):
    __tablename__ = "users"
    id = db.Column(GUID, nullable=False,
                   unique=True, primary_key=True, default=uuid.uuid4)
    name = db.Column(db.String(32), nullable=False, unique=True) # LDAP UID
    public_keys = db.relationship(
        "SSHKey",
        backref="owner",
        cascade="all, delete, delete-orphan",
        single_parent=True,
    )
    role = db.Column(db.Enum(RoleEnum), default=RoleEnum.user, nullable=False)
    created_at = db.Column(
        db.DateTime, default=datetime.utcnow
    )
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    def __str__(self):
        return self.name


class Runtime(db.Model):
    __tablename__ = "runtimes"
    id = db.Column(GUID, nullable=False, unique=True,
                   default=uuid.uuid4, primary_key=True)
    name = db.Column(db.String(256), nullable=False)
    description = db.Column(db.String(256))
    family = db.Column(db.String(256))
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
    id = db.Column(GUID, nullable=False, unique=True,
                   default=uuid.uuid4, primary_key=True)
    runtime_id = db.Column(GUID, db.ForeignKey('runtimes.id'))
    access_level = db.Column(
        db.Enum(RoleEnum), default=RoleEnum.superadmin, nullable=False)
    tag = db.Column(db.String(256), nullable=False)
    name = db.Column(db.String(256), nullable=False)
    description = db.Column(db.String(256))
    value_type = db.Column(db.Enum(OptionValueTypeEnum), nullable=False)
    default_value = db.Column(db.String(256))
    validation_rules = db.relationship(
        "AvailableOptionValidationRule",
        backref="available_option",
        cascade="all, delete, delete-orphan",
        single_parent=True,
    )


class AvailableOptionValidationRule(db.Model):
    __tablename__ = "available_option_validation_rules"
    id = db.Column(GUID, nullable=False, unique=True,
                   default=uuid.uuid4, primary_key=True)
    available_option_id = db.Column(GUID, db.ForeignKey(
        'available_options.id'))
    type = db.Column(db.Enum(ValidationRuleEnum), nullable=False)
    arg = db.Column(db.String(256), nullable=False)


class AddOn(db.Model):
    __tablename__ = "addons"
    id = db.Column(GUID, nullable=False, unique=True,
                   default=uuid.uuid4, primary_key=True)
    runtime_id = db.Column(GUID, db.ForeignKey('runtimes.id'))
    capsule_id = db.Column(GUID, db.ForeignKey('capsules.id'))
    name = db.Column(db.String(256), nullable=False)
    description = db.Column(db.String(256))
    uri = db.Column(db.String(256), nullable=False)
    env = db.Column(db.String(256))
    opts = db.relationship(
        "Option",
        backref="addon",
        cascade="all, delete, delete-orphan",
        single_parent=True,
    )
    quota_volume_size = db.Column(db.String(256), nullable=False)
    quota_memory_max = db.Column(db.String(256), nullable=False)
    quota_cpu_max = db.Column(db.String(256), nullable=False)
    created_at = db.Column(
        db.DateTime, default=datetime.utcnow
    )
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )


class WebApp(db.Model):
    __tablename__ = "webapps"
    id = db.Column(GUID, nullable=False, unique=True,
                   default=uuid.uuid4, primary_key=True)
    runtime_id = db.Column(GUID, db.ForeignKey('runtimes.id'))
    tls_redirect_https = db.Column(db.Boolean, default=True)
    tls_crt = db.Column(db.String(256))
    tls_key = db.Column(db.String(256))
    fqdns = db.relationship(
        "FQDN",
        backref="webapp",
        cascade="all, delete, delete-orphan",
        single_parent=True,
        order_by="asc(FQDN.alias)",
    )
    env = db.Column(db.String(256))
    opts = db.relationship(
        "Option",
        backref="webapp",
        cascade="all, delete, delete-orphan",
        single_parent=True,
    )
    quota_volume_size = db.Column(db.String(256), nullable=False)
    quota_memory_max = db.Column(db.String(256), nullable=False)
    quota_cpu_max = db.Column(db.String(256), nullable=False)
    created_at = db.Column(
        db.DateTime, default=datetime.utcnow
    )
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )


class Option(db.Model):
    # TODO: Check that there is not two foreign ref active / @listens_for
    __tablename__ = "options"
    id = db.Column(GUID, nullable=False, unique=True,
                   default=uuid.uuid4, primary_key=True)
    webapp_id = db.Column(GUID, db.ForeignKey(
        'webapps.id'), nullable=True)
    addon_id = db.Column(GUID, db.ForeignKey(
        'addons.id'), nullable=True)
    tag = db.Column(db.String(256))
    field_name = db.Column(db.String(256))
    value = db.Column(db.String(256))

    @hybrid_property  # @property compliant with SQLAlchemy
    def instance_id(self):
        return self.webapp_id or self.addon_id


class FQDN(db.Model):
    __tablename__ = "fqdns"
    id = db.Column(GUID, nullable=False, unique=True,
                   default=uuid.uuid4, primary_key=True)
    webapp_id = db.Column(GUID, db.ForeignKey('webapps.id'))
    name = db.Column(db.String(256), nullable=False, unique=True)
    alias = db.Column(db.Boolean, nullable=False, default=False)


capsules_users_table = db.Table('capsules_users', db.Model.metadata,
                                db.Column('capsule_id', GUID,
                                          db.ForeignKey('capsules.id')),
                                db.Column('user_id', GUID,
                                          db.ForeignKey('users.id')),
                                )


capsules_sshkeys_table = db.Table('capsules_sshkeys', db.Model.metadata,
                                  db.Column('capsule_id', GUID,
                                            db.ForeignKey('capsules.id')),
                                  db.Column('sshkey_id', GUID,
                                            db.ForeignKey('sshkeys.id')),
                                  )


class SSHKey(db.Model):
    __tablename__ = "sshkeys"
    id = db.Column(GUID, nullable=False, unique=True,
                   default=uuid.uuid4, primary_key=True)
    public_key = db.Column(db.Text, nullable=False)
    user_id = db.Column(GUID, db.ForeignKey(
        'users.id'), nullable=True)
    created_at = db.Column(
        db.DateTime, default=datetime.utcnow
    )
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    def __str__(self):
        return self.public_key


class Capsule(db.Model):
    # TODO quota?
    __tablename__ = "capsules"
    id = db.Column(GUID, nullable=False, unique=True,
                   default=uuid.uuid4, primary_key=True)
    name = db.Column(db.String(256), nullable=False, unique=True) # FIXME: Unique ?
    webapp_id = db.Column(GUID, db.ForeignKey(
        'webapps.id'), nullable=True)
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
    created_at = db.Column(
        db.DateTime, default=datetime.utcnow
    )
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )

# FIXME: Check cross references
# TODO: Check required property


class RuntimeSchema(ma.SQLAlchemyAutoSchema):
    def __init__(self, **kwargs):
        super().__init__(strict=True, **kwargs)

    class Meta:
        model = Runtime
        sqla_session = db.session

    id = ma.auto_field(dump_only=True)
    webapp = fields.Nested('WebAppSchema', default=[], many=True)
    addons = fields.Nested('AddOnSchema', default=[], many=True)
    available_opts = fields.Nested(
        'AvailableOptionSchema', default=[], many=True, exclude=('available_option_id',))
    created_at = ma.auto_field(dump_only=True)
    updated_at = ma.auto_field(dump_only=True)


class AvailableOptionSchema(ma.SQLAlchemyAutoSchema):
    def __init__(self, **kwargs):
        super().__init__(strict=True, **kwargs)

    class Meta:
        model = AvailableOption
        sqla_session = db.session

    validation_rules = fields.Nested(
        'AvailableOptionValidationRuleSchema', default=[], many=True, exclude=('validation_rule_id',))


class AvailableOptionValidationRuleSchema(ma.SQLAlchemyAutoSchema):
    def __init__(self, **kwargs):
        super().__init__(strict=True, **kwargs)

    class Meta:
        model = AvailableOptionValidationRule
        sqla_session = db.session


class WebAppSchema(ma.SQLAlchemyAutoSchema):
    def __init__(self, **kwargs):
        super().__init__(strict=True, **kwargs)

    class Meta:
        model = WebApp
        sqla_session = db.session

    id = ma.auto_field(dump_only=True)
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


class AddOnSchema(ma.SQLAlchemyAutoSchema):
    def __init__(self, **kwargs):
        super().__init__(strict=True, **kwargs)

    class Meta:
        model = AddOn
        sqla_session = db.session

    id = ma.auto_field(dump_only=True)
    uri = ma.auto_field(dump_only=True)
    opts = fields.Nested(
        "OptionSchema",
        default=[],
        many=True,
        only=('tag', 'field_name', 'value'),
    )
    created_at = ma.auto_field(dump_only=True)
    updated_at = ma.auto_field(dump_only=True)


class OptionSchema(ma.SQLAlchemyAutoSchema):
    def __init__(self, **kwargs):
        super().__init__(strict=True, **kwargs)

    class Meta:
        model = Option
        sqla_session = db.session


class FQDNSchema(ma.SQLAlchemyAutoSchema):
    def __init__(self, **kwargs):
        super().__init__(strict=True, **kwargs)

    class Meta:
        model = FQDN
        sqla_session = db.session


class SSHKeySchema(ma.SQLAlchemyAutoSchema):
    def __init__(self, **kwargs):
        super().__init__(strict=True, **kwargs)

    class Meta:
        model = SSHKey
        sqla_session = db.session

    created_at = ma.auto_field(dump_only=True)
    updated_at = ma.auto_field(dump_only=True)


class CapsuleSchema(ma.SQLAlchemyAutoSchema):
    def __init__(self, **kwargs):
        super().__init__(strict=True, **kwargs)

    class Meta:
        model = Capsule
        include_relationships = True
        include_fk = True
        exclude = ('webapp_id',)
        sqla_session = db.session

    id = ma.auto_field(dump_only=True)
    owners = fields.List(fields.String())
    authorized_keys = fields.List(fields.String())
    created_at = ma.auto_field(dump_only=True)
    updated_at = ma.auto_field(dump_only=True)


capsule_schema = CapsuleSchema()
capsules_schema = CapsuleSchema(many=True)
runtime_schema = RuntimeSchema()
runtimes_schema = RuntimeSchema(many=True)