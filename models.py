import enum
import uuid
from datetime import datetime
from app import db, ma
from marshmallow import fields, post_dump
from marshmallow_enum import EnumField
from sqlalchemy.orm import backref
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.types import TypeDecorator, CHAR
from sqlalchemy.dialects.postgresql import UUID
from ast import literal_eval


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
    __default_filter__ = "name"

    id = db.Column(GUID, nullable=False,
                   unique=True, primary_key=True, default=uuid.uuid4)
    name = db.Column(db.String(32), nullable=False, unique=True)  # LDAP UID
    public_keys = db.relationship(
        "SSHKey",
        backref="owner",
        cascade="all, delete, delete-orphan",
        single_parent=True,
    )
    apptokens = db.relationship(
        "AppToken",
        backref="user",
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
    desc = db.Column(db.String(256), nullable=False)
    fam = db.Column(db.String(256), nullable=False)
    runtime_type = db.Column(db.Enum(RuntimeTypeEnum), nullable=False)
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
    field_name = db.Column(db.String(256), nullable=False)
    field_description = db.Column(db.String(256))
    value_type = db.Column(db.Enum(OptionValueTypeEnum), nullable=False)
    default_value = db.Column(db.String(256), nullable=True)
    validation_rules = db.relationship(
        "AvailableOptionValidationRule",
        backref="available_option",
        cascade="all, delete, delete-orphan",
        single_parent=True,
    )

    @staticmethod
    def create(available_opts_array):
        available_opts = []
        for opt in available_opts_array:
            if "validation_rules" in opt:
                validation_rules_array = opt["validation_rules"]
                validation_rules = []
                for rule in validation_rules_array:
                    validation_rule = AvailableOptionValidationRule(**rule)
                    validation_rules.append(validation_rule)
                opt.pop("validation_rules")
                available_opt = AvailableOption(
                    **opt,
                    validation_rules=validation_rules
                )
            else:
                available_opt = AvailableOption(**opt)
            available_opts.append(available_opt)

        return available_opts


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
    uri = db.Column(db.String(256))
    env = db.Column(db.Text)
    opts = db.relationship(
        "Option",
        backref="addon",
        cascade="all, delete, delete-orphan",
        single_parent=True,
    )
    quota_volume_size = db.Column(db.String(256))
    quota_memory_max = db.Column(db.String(256))
    quota_cpu_max = db.Column(db.String(256))
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
    tls_crt = db.Column(db.Text)
    tls_key = db.Column(db.Text)
    fqdns = db.relationship(
        "FQDN",
        backref="webapp",
        cascade="all, delete, delete-orphan",
        single_parent=True,
        order_by="asc(FQDN.alias)",
    )
    env = db.Column(db.Text)
    opts = db.relationship(
        "Option",
        backref="webapp",
        cascade="all, delete, delete-orphan",
        single_parent=True,
    )
    quota_volume_size = db.Column(db.String(256))
    quota_memory_max = db.Column(db.String(256))
    quota_cpu_max = db.Column(db.String(256))
    created_at = db.Column(
        db.DateTime, default=datetime.utcnow
    )
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )


class Option(db.Model):
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

    @staticmethod
    def create(opts):
        opts_array = []
        for opt in opts:
            opts_array.append(Option(**opt))
        return opts_array


class FQDN(db.Model):
    __tablename__ = "fqdns"
    id = db.Column(GUID, nullable=False, unique=True,
                   default=uuid.uuid4, primary_key=True)
    webapp_id = db.Column(GUID, db.ForeignKey('webapps.id'))
    name = db.Column(db.String(256), nullable=False)
    alias = db.Column(db.Boolean, nullable=False, default=False)

    @staticmethod
    def create(fqdns):
        fqdns_array = []
        for fqdn in fqdns:
            fqdns_array.append(FQDN(**fqdn))
        return fqdns_array


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
    __tablename__ = "capsules"
    id = db.Column(GUID, nullable=False, unique=True,
                   default=uuid.uuid4)
    uid = db.Column(db.Integer, primary_key=True,
                    unique=True, autoincrement=True)
    name = db.Column(db.String(256), nullable=False, unique=True)
    webapp_id = db.Column(GUID, db.ForeignKey(
        'webapps.id'), nullable=True)

    # One-To-One
    # 1 (capsule) To 0..1 (webapp)
    webapp = db.relationship(
        "WebApp",
        backref=backref("capsule", uselist=False),
        cascade="all, delete, delete-orphan",
        single_parent=True,
    )

    # One-To-Many
    # 1 (capsule) To 0..N (addons)
    addons = db.relationship(
        "AddOn",
        backref="capsule",
        cascade="all, delete, delete-orphan",
        single_parent=True,
    )

    # Many-To-Many
    # 1..N (capsules) To 0..N (sshkeys)
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


class AppToken(db.Model):
    __tablename__ = "apptokens"
    id = db.Column(GUID, nullable=False, unique=True,
                   default=uuid.uuid4, primary_key=True)
    app = db.Column(db.String(256), nullable=False)
    owner_id = db.Column(GUID, db.ForeignKey('users.id'))
    token = db.Column(db.String(256), nullable=False, unique=True)
    created_at = db.Column(
        db.DateTime, default=datetime.utcnow
    )
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )


class RuntimeSchema(ma.SQLAlchemyAutoSchema):
    def __init__(self, **kwargs):
        super().__init__(strict=True, **kwargs)

    class Meta:
        model = Runtime
        include_relationships = True
        include_fk = True
        sqla_session = db.session

    id = ma.auto_field(dump_only=True)

    runtime_type = EnumField(RuntimeTypeEnum, by_value=True)

    # webapps = fields.Nested(
    #     'WebAppSchema',
    #     default=[],
    #     many=True,
    #     only=('capsule_id', 'id'),
    # )
    # addons = fields.Nested(
    #     'AddOnSchema',
    #     default=[],
    #     many=True,
    #     only=('capsule_id', 'id'),
    # )
    available_opts = fields.Nested(
        'AvailableOptionSchema',
        default=[],
        many=True,
        exclude=('available_option_id',)
    )
    created_at = ma.auto_field(dump_only=True)
    updated_at = ma.auto_field(dump_only=True)

    @post_dump()
    def __post_dump(self, data):
        if 'webapps' in data:
            data['webapps'] = list(map(str, data['webapps']))
        if 'addons' in data:
            data['addons'] = list(map(str, data['addons']))


class AvailableOptionSchema(ma.SQLAlchemyAutoSchema):
    def __init__(self, **kwargs):
        super().__init__(strict=True, **kwargs)

    class Meta:
        model = AvailableOption
        sqla_session = db.session

    access_level = EnumField(RoleEnum, by_value=True)
    value_type = EnumField(OptionValueTypeEnum, by_value=True)

    validation_rules = fields.Nested(
        'AvailableOptionValidationRuleSchema',
        default=[],
        many=True,
        exclude=('validation_rule_id',)
    )


class AvailableOptionValidationRuleSchema(ma.SQLAlchemyAutoSchema):
    def __init__(self, **kwargs):
        super().__init__(strict=True, **kwargs)

    class Meta:
        model = AvailableOptionValidationRule
        sqla_session = db.session

    type = EnumField(ValidationRuleEnum, by_value=True)


class WebAppSchema(ma.SQLAlchemyAutoSchema):
    def __init__(self, **kwargs):
        super().__init__(strict=True, **kwargs)

    class Meta:
        model = WebApp
        # include_relationships = True
        include_fk = True
        # exclude = ('runtime',)
        sqla_session = db.session

    id = ma.auto_field(dump_only=True)
    fqdns = fields.Nested("FQDNSchema", default=[], many=True, exclude=('id',))
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
        # include_relationships = True
        include_fk = True
        # exclude = ('runtime',)
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
        include_relationships = True
        sqla_session = db.session

    owner = fields.String()
    created_at = ma.auto_field(dump_only=True)
    updated_at = ma.auto_field(dump_only=True)


class CapsuleInputSchema(ma.SQLAlchemyAutoSchema):
    def __init__(self, **kwargs):
        super().__init__(strict=True, **kwargs)

    class Meta:
        model = Capsule
        include_relationships = True
        include_fk = True
        exclude = ('webapp_id',)
        sqla_session = db.session

    id = ma.auto_field(dump_only=True)
    uid = ma.auto_field(dump_only=True)
    owners = fields.List(fields.String())
    authorized_keys = fields.List(fields.String())
    created_at = ma.auto_field(dump_only=True)
    updated_at = ma.auto_field(dump_only=True)

    # https://stackoverflow.com/questions/56779627/serialize-uuids-with-marshmallow-sqlalchemy
    @post_dump()
    def __post_dump(self, data):
        if 'webapp' in data:
            data['webapp'] = str(data['webapp'])
        if 'addons' in data:
            data['addons'] = list(map(str, data['addons']))


class CapsuleOutputSchema(ma.SQLAlchemyAutoSchema):
    def __init__(self, **kwargs):
        super().__init__(strict=True, **kwargs)

    class Meta:
        model = Capsule
        include_relationships = True
        include_fk = True
        exclude = ('webapp_id',)
        sqla_session = db.session

    id = ma.auto_field(dump_only=True)
    uid = ma.auto_field(dump_only=True)
    owners = fields.List(fields.String())
    authorized_keys = fields.Nested(
        "SSHKeySchema",
        default=[],
        many=True,
        only=('id', 'public_key'),
    )
    created_at = ma.auto_field(dump_only=True)
    updated_at = ma.auto_field(dump_only=True)

    # https://stackoverflow.com/questions/56779627/serialize-uuids-with-marshmallow-sqlalchemy
    @post_dump()
    def __post_dump(self, data):
        if 'webapp' in data:
            data['webapp'] = str(data['webapp'])
        if 'addons' in data:
            data['addons'] = list(map(str, data['addons']))


class CapsuleSchemaVerbose(ma.SQLAlchemyAutoSchema):
    def __init__(self, **kwargs):
        super().__init__(strict=True, **kwargs)

    class Meta:
        model = Capsule
        include_relationships = True
        include_fk = True
        exclude = ('webapp_id',)
        sqla_session = db.session

    id = ma.auto_field(dump_only=True)
    uid = ma.auto_field(dump_only=True)
    addons = fields.Nested(
        "AddOnSchema",
        default=[],
        many=True,
        exclude=('created_at', 'updated_at')
    )
    webapp = fields.Nested(
        "WebAppSchema",
        default={},
        many=False,
        exclude=('created_at', 'updated_at')
    )
    owners = fields.Nested(
        "UserSchema",
        default=[],
        many=True,
        exclude=('created_at', 'updated_at')
    )
    authorized_keys = fields.Nested(
        "SSHKeySchema",
        default=[],
        many=True,
        only=('id', 'public_key'),
    )
    created_at = ma.auto_field(dump_only=True)
    updated_at = ma.auto_field(dump_only=True)

    @post_dump()
    def __post_dump(self, data):
        if ('webapp' in data) and (data['webapp'] is not None):
            if ('env' in data["webapp"]) \
                    and (data['webapp']['env'] is not None):
                data['webapp']['env'] = literal_eval(data['webapp']['env'])
            else:
                data['webapp']['env'] = dict()
        else:
            data['webapp'] = {}
        if 'addons' in data:
            for addon in data['addons']:
                if ('env' in addon) and (addon['env'] is not None):
                    addon['env'] = literal_eval(addon['env'])
                else:
                    addon['env'] = dict()


class UserSchema(ma.SQLAlchemyAutoSchema):
    def __init__(self, **kwargs):
        super().__init__(strict=True, **kwargs)

    class Meta:
        model = User
        sqla_session = db.session

    id = ma.auto_field(dump_only=True)
    public_keys = fields.Nested(
        "SSHKeySchema",
        default=[],
        many=True,
        only=('id', 'public_key'),
    )
    role = EnumField(RoleEnum, by_value=True)
    created_at = ma.auto_field(dump_only=True)
    updated_at = ma.auto_field(dump_only=True)


class AppTokenSchema(ma.SQLAlchemyAutoSchema):
    def __init__(self, **kwargs):
        super().__init__(strict=True, **kwargs)

    class Meta:
        model = AppToken
        sqla_session = db.session

    id = ma.auto_field(dump_only=True)
    created_at = ma.auto_field(dump_only=True)
    updated_at = ma.auto_field(dump_only=True)


capsule_input_schema = CapsuleInputSchema()
capsule_output_schema = CapsuleOutputSchema()
capsules_output_schema = CapsuleOutputSchema(many=True)
capsule_verbose_schema = CapsuleSchemaVerbose()
capsules_verbose_schema = CapsuleSchemaVerbose(many=True)
runtime_schema = RuntimeSchema()
runtimes_schema = RuntimeSchema(many=True)
sshkey_schema = SSHKeySchema()
sshkeys_schema = SSHKeySchema(many=True)
user_schema = UserSchema()
users_schema = UserSchema(many=True)
webapp_schema = WebAppSchema()
addon_schema = AddOnSchema()
addons_schema = AddOnSchema(many=True)
apptoken_schema = AppTokenSchema()
apptokens_schema = AppTokenSchema(many=True)
