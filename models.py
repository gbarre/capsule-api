import enum

from exceptions import FQDNAlreadyExists
import uuid
from datetime import datetime
from app import db, ma
from marshmallow import fields, post_dump, pre_load
from marshmallow_enum import EnumField
from sqlalchemy.orm import backref
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.types import TypeDecorator, CHAR
from sqlalchemy.dialects.postgresql import UUID
from ast import literal_eval
from werkzeug.exceptions import BadRequest, Forbidden
import re
import json
import string
import random


class GUID(TypeDecorator):
    """Platform-independent GUID type.

    Uses PostgreSQL's UUID type, otherwise uses
    CHAR(32), storing as stringified hex values.

    """
    impl = CHAR

    def load_dialect_impl(self, dialect):
        if dialect.name == 'postgresql':
            return dialect.type_descriptor(UUID())  # pragma: no cover
        else:
            return dialect.type_descriptor(CHAR(32))

    def process_bind_param(self, value, dialect):
        if value is None:
            return value
        elif dialect.name == 'postgresql':
            return str(value)  # pragma: no cover
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
        return NotImplemented  # pragma: no cover

    def __gt__(self, other):
        if self.__class__ is other.__class__:
            return self.getpower() > other.getpower()
        return NotImplemented  # pragma: no cover

    def __le__(self, other):
        if self.__class__ is other.__class__:
            return self.getpower() <= other.getpower()
        return NotImplemented  # pragma: no cover

    def __lt__(self, other):
        if self.__class__ is other.__class__:
            return self.getpower() < other.getpower()
        return NotImplemented  # pragma: no cover


class OptionValueTypeEnum(str, enum.Enum):
    integer = "integer"
    float = "float"
    boolean = "boolean"
    string = "string"
    base64 = "base64"


class ValidationRuleEnum(str, enum.Enum):
    regex = "regex"
    min = "min"
    max = "max"
    eq = "eq"
    neq = "neq"
    format = "format"  # check file format
    into = "into"


class SizeEnum(str, enum.Enum):
    tiny = "tiny"
    small = "small"
    medium = "medium"
    large = "large"
    xlarge = "xlarge"

    def getparts(self):
        if self == __class__.tiny:
            return 2
        if self == __class__.small:
            return 4
        if self == __class__.medium:
            return 8
        if self == __class__.large:
            return 16
        if self == __class__.xlarge:
            return 32


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
    parts_manager = db.Column(db.Boolean, nullable=False, default=False)
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
    description = db.Column(db.String(256), nullable=False)
    fam = db.Column(db.String(256), nullable=False)
    runtime_type = db.Column(db.Enum(RuntimeTypeEnum), nullable=False)
    uri_template = db.Column(db.Text, nullable=True)
    webapps = db.relationship(
        "WebApp",
        backref="runtime",
        single_parent=True,
        cascade="all, delete, delete-orphan",
    )
    addons = db.relationship(
        "AddOn",
        backref="runtime",
        single_parent=True,
        cascade="all, delete, delete-orphan",
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
        return self.webapps or self.addons  # pragma: no cover

    def generate_uri_dbname(self, capsule):
        dbname = None
        if self.uri_template is not None:
            template = json.loads(self.uri_template)
            pattern = template['pattern']
            variables = template['variables']
            d_vars = {}
            for variable in variables:
                value = self._generate_variable(
                    src=variable['src'],
                    length=variable['length'],
                    unique=variable['unique'],
                    capsule=capsule,
                    offset=capsule.addons_offset + 1,
                )
                d_vars[variable['name']] = value
                if variable['set_name'] and \
                   (variable['src'] == 'capsule') and \
                   variable['unique']:
                    dbname = value

            res = pattern.format(**d_vars)
            return (res, dbname)
        else:
            return (None, dbname)

    def _generate_variable(self, src, length, unique=None,
                           capsule=None, offset=1):
        res = ""
        if src == 'capsule':
            name = capsule.name.replace('-', '')[:8]
            uid = str(capsule.uid)
            ll = len(name) + len(uid) + len(str(offset))
            if ll < length:
                diff = length - ll
                capsule_id = str(capsule.id).replace('-', '')[:diff]
            else:  # pragma: no cover
                # Corner case
                return self._generate_variable(src='random', length=length)
            res = name + uid + capsule_id + str(offset)

            # uniqueness
            # TODO: not optimal at all because maybe there are lot of
            #       recursions and one SQL request for each call.
            #       And what happens when there are the same request
            #       in the same moment (race conditions etc).
            if unique:
                addon = AddOn.query\
                    .filter(AddOn.uri.like(f"%{res}%")).one_or_none()
                if addon is not None:
                    return self._generate_variable(  # pragma: no cover
                        src=src,
                        length=length,
                        unique=unique,
                        capsule=capsule,
                        offset=offset + 1,
                    )
                else:  # set capsule.addons_offset
                    capsule.addons_offset = offset
                    db.session.commit()

        elif src == 'random':
            lettersAndDigits = string.ascii_letters + string.digits
            res = ''.join(
                (random.choice(lettersAndDigits) for i in range(length))
            )

        return res


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
    default_value = db.Column(db.Text, nullable=True)
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
    env = db.Column(db.Text)
    opts = db.relationship(
        "Option",
        backref="webapp",
        cascade="all, delete, delete-orphan",
        single_parent=True,
    )
    volume_size = db.Column(
        db.Integer,
        nullable=False,
        default=10  # Only for migration, else default is setted by the config
    )
    crons = db.relationship(
        "Cron",
        backref="webapp",
        cascade="all, delete, delete-orphan",
        single_parent=True,
    )
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
    value = db.Column(db.Text)
    value_type = db.Column(
        db.Enum(OptionValueTypeEnum),
        nullable=False,
        default=OptionValueTypeEnum.string
    )

    @hybrid_property  # @property compliant with SQLAlchemy
    def instance_id(self):
        return self.webapp_id or self.addon_id  # pragma: no cover

    @staticmethod
    def create(opts, runtime_id, user_role):
        opts_array = []
        for opt in opts:
            try:
                opt_tag = opt['tag']
                opt_name = opt['field_name']
                opt_value = opt['value']
            except KeyError as e:
                raise BadRequest(description=f"{str(e)} is required for opts")

            available_opt = AvailableOption.query\
                .filter_by(
                    runtime_id=runtime_id,
                    tag=opt_tag,
                    field_name=opt_name
                ).first()
            if available_opt is None:
                raise BadRequest(description="This option is not available: "
                                 f"field_name='{opt_name}', tag='{opt_tag}'")

            opt['value_type'] = available_opt.value_type

            # Check access_level
            if user_role < available_opt.access_level:
                raise Forbidden(description="You don't have permission to set "
                                            f"the option '{opt_name}'")

            rules = AvailableOptionValidationRule.query\
                .filter_by(available_option_id=available_opt.id).all()

            if rules is not None:
                for rule in rules:  # TODO: test all rules!
                    if rule.type == ValidationRuleEnum.regex:
                        regex = re.compile(rule.arg)
                        if regex.match(opt_value) is None:
                            raise BadRequest(description=f"'{opt_name}' must "
                                             f"match python regex {rule.arg}")
                    elif rule.type == ValidationRuleEnum.min\
                            and __class__.is_less_than(
                                option_value_type=available_opt.value_type,
                                option_value=opt_value,
                                rule_value=rule.arg):
                        raise BadRequest(description=f"'{opt_name}' cannot be "
                                         f"less than {rule.arg}")
                    elif rule.type == ValidationRuleEnum.max\
                            and __class__.is_greater_than(
                                option_value_type=available_opt.value_type,
                                option_value=opt_value,
                                rule_value=rule.arg):
                        raise BadRequest(description=f"'{opt_name}' cannot be "
                                         f"greater than {rule.arg}")
                    elif rule.type == ValidationRuleEnum.eq\
                            and opt_value != rule.arg:
                        raise BadRequest(description=f"'{opt_name}' cannot be "
                                         f"different from {rule.arg}")
                    elif rule.type == ValidationRuleEnum.neq\
                            and opt_value == rule.arg:
                        raise BadRequest(description=f"'{opt_name}' cannot be "
                                         f"equal to {rule.arg}")
                    # TODO : check base64 format
                    # elif rule.type == ValidationRuleEnum.format:
                    #     opt_value must be base64 encoded
                    #     and opt_value is not rule.arg
                    #     raise BadRequest
                    elif rule.type == ValidationRuleEnum.into\
                            and opt_value not in rule.arg:
                        raise BadRequest(description=f"'{opt_name}' must be "
                                         f"in {rule.arg}")

            opts_array.append(Option(**opt))
        return opts_array

    @staticmethod
    def is_less_than(option_value_type, option_value, rule_value):
        if option_value_type is OptionValueTypeEnum.integer:
            try:
                return int(option_value) < int(rule_value)
            except ValueError:  # pragma: no cover
                raise BadRequest(description=f"'{option_value}' is not "
                                 "an integer")
        elif option_value_type \
                is OptionValueTypeEnum.float:  # pragma: no cover
            try:
                return float(option_value) < float(rule_value)
            except ValueError:
                raise BadRequest(description=f"'{option_value}' is not "
                                 "a float")
        else:  # pragma: no cover
            raise BadRequest(description="Something went wrong while "
                             "convert string...")

    @staticmethod
    def is_greater_than(option_value_type, option_value, rule_value):
        if option_value_type is OptionValueTypeEnum.integer:
            try:
                return int(option_value) > int(rule_value)
            except ValueError:  # pragma: no cover
                raise BadRequest(description=f"'{option_value}' is not "
                                 "an integer")
        elif option_value_type \
                is OptionValueTypeEnum.float:  # pragma: no cover
            try:
                return float(option_value) > float(rule_value)
            except ValueError:  # pragma: no cover
                raise BadRequest(description=f"'{option_value}' is not "
                                 "a float")
        else:  # pragma: no cover
            raise BadRequest(description="Something went wrong while "
                             "convert string...")


class FQDN(db.Model):
    __tablename__ = "fqdns"
    id = db.Column(GUID, nullable=False, unique=True,
                   default=uuid.uuid4, primary_key=True)
    capsule_id = db.Column(GUID, db.ForeignKey('capsules.id'))
    name = db.Column(db.String(256), nullable=False, unique=True)
    alias = db.Column(db.Boolean, nullable=False, default=False)

    @staticmethod
    def create(fqdns, webapp_id=None):
        fqdns_array = []
        for fqdn in fqdns:
            existing_fqdn = FQDN.query.\
                filter_by(name=fqdn['name']).one_or_none()
            if existing_fqdn is None or webapp_id == existing_fqdn.webapp_id:
                fqdns_array.append(FQDN(**fqdn))
            else:
                raise FQDNAlreadyExists(fqdn['name'])
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


class Capsule(db.Model):
    __tablename__ = "capsules"
    id = db.Column(GUID, nullable=False, unique=True,
                   default=uuid.uuid4)
    uid = db.Column(db.Integer, primary_key=True,
                    unique=True, autoincrement=True)
    name = db.Column(db.String(256), nullable=False, unique=True)
    no_update = db.Column(
        db.DateTime, nullable=False, default=datetime(1970, 1, 1)
    )
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

    enable_https = db.Column(db.Boolean, default=True)
    force_redirect_https = db.Column(db.Boolean, default=True)
    tls_crt = db.Column(db.Text)
    tls_key = db.Column(db.Text)
    fqdns = db.relationship(
        "FQDN",
        backref="capsule",
        cascade="all, delete, delete-orphan",
        single_parent=True,
        order_by="asc(FQDN.alias)",
    )

    # One-To-Many
    # 1 (capsule) To 0..N (addons)
    addons = db.relationship(
        "AddOn",
        backref="capsule",
        cascade="all, delete, delete-orphan",
        single_parent=True,
    )

    addons_offset = db.Column(db.Integer, default=0, nullable=False)

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
    comment = db.Column(db.Text)
    delegate_fqdns = db.Column(
        db.Boolean,
        nullable=False,
        default=False
    )
    delegate_tls = db.Column(
        db.Boolean,
        nullable=False,
        default=False
    )
    size = db.Column(db.Enum(SizeEnum), default=SizeEnum.tiny, nullable=False)
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


class Cron(db.Model):
    __tablename__ = "crons"
    id = db.Column(GUID, nullable=False, unique=True,
                   default=uuid.uuid4, primary_key=True)
    webapp_id = db.Column(GUID, db.ForeignKey('webapps.id'))
    command = db.Column(db.String(256), nullable=False)
    hour = db.Column(db.String(256), default="*")
    minute = db.Column(db.String(256), default="0")
    month = db.Column(db.String(256), default="*")
    month_day = db.Column(db.String(256), default="*")
    week_day = db.Column(db.String(256), default="*")
    created_at = db.Column(
        db.DateTime, default=datetime.utcnow
    )
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )


class RuntimeSchema(ma.SQLAlchemyAutoSchema):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    class Meta:
        model = Runtime
        include_relationships = True
        include_fk = True
        sqla_session = db.session

    id = ma.auto_field(dump_only=True)

    runtime_type = EnumField(RuntimeTypeEnum, by_value=True)
    available_opts = fields.Nested(
        'AvailableOptionSchema',
        default=[],
        many=True,
        # exclude=('available_option_idddd',)
    )
    created_at = ma.auto_field(dump_only=True)
    updated_at = ma.auto_field(dump_only=True)

    @post_dump()
    def __post_dump(self, data, **kwargs):
        if 'webapps' in data:
            data['webapps'] = list(map(str, data['webapps']))
        if 'addons' in data:
            data['addons'] = list(map(str, data['addons']))

        if (data['uri_template'] is not None) \
                and (isinstance(data['uri_template'], str)) \
                and (len(data['uri_template']) > 0):
            # string =====================> json / object
            data['uri_template'] = json.loads(data['uri_template'])
        return data

    @pre_load()
    def __pre_load(self, data, **kwargs):
        if 'uri_template' in data and data['uri_template'] is not None:
            # ensure uri_template is correct
            variables = data['uri_template']['variables']
            for variable in variables:
                length = variable['length']
                unique = variable['unique']
                src = variable['src']
                if unique and src == 'random':
                    msg = "Uniqueness is not taken into account "\
                          "for a random variable."
                    raise BadRequest(description=msg)
                if unique and length < 16 and src == 'capsule':
                    msg = "Uniqueness of a variable required "\
                          "a length greater or equal to 16."
                    raise BadRequest(description=msg)
            # json / object =====================> string
            data['uri_template'] = json.dumps(data['uri_template'])
        return data


class AvailableOptionSchema(ma.SQLAlchemyAutoSchema):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    class Meta:
        model = AvailableOption
        sqla_session = db.session

    access_level = EnumField(RoleEnum, by_value=True)
    value_type = EnumField(OptionValueTypeEnum, by_value=True)

    validation_rules = fields.Nested(
        'AvailableOptionValidationRuleSchema',
        default=[],
        many=True,
        # exclude=('validation_rule_id',)
    )


class AvailableOptionValidationRuleSchema(ma.SQLAlchemyAutoSchema):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    class Meta:
        model = AvailableOptionValidationRule
        sqla_session = db.session

    type = EnumField(ValidationRuleEnum, by_value=True)


class WebAppSchema(ma.SQLAlchemyAutoSchema):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    class Meta:
        model = WebApp
        include_relationships = True
        include_fk = True
        exclude = ('runtime',)
        sqla_session = db.session

    id = ma.auto_field(dump_only=True)
    opts = fields.Nested(
        "OptionSchema",
        default=[],
        many=True,
        only=('tag', 'field_name', 'value', 'value_type',),
    )
    crons = fields.Nested(
        "CronSchema",
        default=[],
        many=True,
        exclude=('id', 'created_at', 'updated_at'),
    )
    created_at = ma.auto_field(dump_only=True)
    updated_at = ma.auto_field(dump_only=True)

    @post_dump()
    def __post_dump(self, data, **kwargs):
        if (data['env'] is not None) and (isinstance(data['env'], str)) \
                and (len(data['env']) > 0):
            data['env'] = literal_eval(data['env'])
        else:
            data['env'] = {}
        return data

    @pre_load()
    def __pre_load(self, data, **kwargs):
        if ('env' in data) and (data['env'] is not None):
            data['env'] = json.dumps(data['env'])
        else:
            data['env'] = ""
        return data


class WebAppNatsSchema(ma.SQLAlchemyAutoSchema):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    class Meta:
        model = WebApp
        include_fk = True
        sqla_session = db.session

    id = ma.auto_field(dump_only=True)
    opts = fields.Nested(
        "OptionSchema",
        default=[],
        many=True,
        only=('tag', 'field_name', 'value', 'value_type',),
    )
    crons = fields.Nested(
        "CronSchema",
        default=[],
        many=True,
        exclude=('id', 'created_at', 'updated_at'),
    )
    created_at = ma.auto_field(dump_only=True)
    updated_at = ma.auto_field(dump_only=True)

    @post_dump()
    def __post_dump(self, data, **kwargs):
        if (data['env'] is not None) and (isinstance(data['env'], str)) \
                and (len(data['env']) > 0):
            data['env'] = literal_eval(data['env'])
        else:
            data['env'] = {}
        return data

    @pre_load()
    def __pre_load(self, data, **kwargs):
        if ('env' in data) and (data['env'] is not None):
            data['env'] = json.dumps(data['env'])
        else:
            data['env'] = ""
        return data


class AddOnSchema(ma.SQLAlchemyAutoSchema):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    class Meta:
        model = AddOn
        include_fk = True
        sqla_session = db.session

    id = ma.auto_field(dump_only=True)
    name = ma.auto_field(dump_only=True)
    uri = ma.auto_field(dump_only=True)
    opts = fields.Nested(
        "OptionSchema",
        default=[],
        many=True,
        only=('tag', 'field_name', 'value'),
    )
    created_at = ma.auto_field(dump_only=True)
    updated_at = ma.auto_field(dump_only=True)

    @post_dump()
    def __post_dump(self, data, **kwargs):
        if (data['env'] is not None) and (isinstance(data['env'], str)) \
                and (len(data['env']) > 0):
            data['env'] = literal_eval(data['env'])
        else:
            data['env'] = {}
        return data

    @pre_load()
    def __pre_load(self, data, **kwargs):
        if ('env' in data) and (data['env'] is not None):
            data['env'] = json.dumps(data['env'])
        else:
            data['env'] = ""
        return data


class OptionSchema(ma.SQLAlchemyAutoSchema):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    class Meta:
        model = Option
        sqla_session = db.session


class FQDNSchema(ma.SQLAlchemyAutoSchema):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    class Meta:
        model = FQDN
        sqla_session = db.session
        id = ma.auto_field(dump_only=True)


class SSHKeySchema(ma.SQLAlchemyAutoSchema):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    class Meta:
        model = SSHKey
        include_relationships = False
        sqla_session = db.session

    created_at = ma.auto_field(dump_only=True)
    updated_at = ma.auto_field(dump_only=True)


class CapsuleInputSchema(ma.SQLAlchemyAutoSchema):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

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
    fqdns = fields.Nested("FQDNSchema", default=[], many=True, exclude=('id',))
    tls_crt = ma.auto_field(load_only=True)
    tls_key = ma.auto_field(load_only=True)
    size = EnumField(SizeEnum, by_value=True)
    created_at = ma.auto_field(dump_only=True)
    updated_at = ma.auto_field(dump_only=True)

    # https://stackoverflow.com/questions/56779627/serialize-uuids-with-marshmallow-sqlalchemy
    @post_dump()
    def __post_dump(self, data, **kwargs):
        if 'webapp' in data:
            data['webapp'] = str(data['webapp'])
        if 'addons' in data:
            data['addons'] = list(map(str, data['addons']))
        if data['comment'] is None:
            data['comment'] = ""
        return data


class CapsuleOutputSchema(ma.SQLAlchemyAutoSchema):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

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
    )
    fqdns = fields.Nested("FQDNSchema", default=[], many=True)
    tls_crt = ma.auto_field(load_only=True)
    tls_key = ma.auto_field(load_only=True)
    size = EnumField(SizeEnum, by_value=True)
    created_at = ma.auto_field(dump_only=True)
    updated_at = ma.auto_field(dump_only=True)

    # https://stackoverflow.com/questions/56779627/serialize-uuids-with-marshmallow-sqlalchemy
    @post_dump()
    def __post_dump(self, data, **kwargs):
        if 'webapp' in data and data['webapp'] is not None:
            data['webapp'] = str(data['webapp'])
        if 'addons' in data:
            data['addons'] = list(map(str, data['addons']))
        if data['comment'] is None:
            data['comment'] = ""
        return data


class CapsuleSchemaVerbose(ma.SQLAlchemyAutoSchema):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

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
    fqdns = fields.Nested("FQDNSchema", default=[], many=True)
    tls_crt = ma.auto_field(load_only=True)
    tls_key = ma.auto_field(load_only=True)
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
    )
    size = EnumField(SizeEnum, by_value=True)
    created_at = ma.auto_field(dump_only=True)
    updated_at = ma.auto_field(dump_only=True)

    @post_dump()
    def __post_dump(self, data, **kwargs):
        if ('webapp' in data) and (data['webapp'] is not None):
            if ('env' in data["webapp"]) \
                    and (data['webapp']['env'] is not None) \
                    and (isinstance(data['webapp']['env'], str)) \
                    and (len(data['webapp']['env']) > 0):
                data['webapp']['env'] = literal_eval(data['webapp']['env'])
        else:
            data['webapp'] = {}
        if 'addons' in data:
            for addon in data['addons']:
                if ('env' in addon) and (addon['env'] is not None) \
                        and (isinstance(addon['env'], str)) \
                        and (len(addon['env']) > 0):
                    addon['env'] = literal_eval(addon['env'])
        if data['comment'] is None:
            data['comment'] = ""
        return data

    @pre_load()
    def __pre_load(self, data, **kwargs):
        if ('webapp' in data) and (data['webapp'] is not None):
            if ('env' in data["webapp"]) \
                    and (data['webapp']['env'] is not None):
                data['webapp']['env'] = json.dumps(data['webapp']['env'])
        else:
            data['webapp'] = {}
        if 'addons' in data:
            for addon in data['addons']:
                if ('env' in addon) and (addon['env'] is not None):
                    addon['env'] = json.dumps(addon['env'])
        return data


class CapsuleNatsSchema(ma.SQLAlchemyAutoSchema):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

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
    fqdns = fields.Nested("FQDNSchema", default=[], many=True)
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
    )
    size = EnumField(SizeEnum, by_value=True)
    created_at = ma.auto_field(dump_only=True)
    updated_at = ma.auto_field(dump_only=True)

    @post_dump()
    def __post_dump(self, data, **kwargs):
        if ('webapp' in data) and (data['webapp'] is not None):
            if ('env' in data["webapp"]) \
                    and (data['webapp']['env'] is not None) \
                    and (isinstance(data['webapp']['env'], str)) \
                    and (len(data['webapp']['env']) > 0):
                data['webapp']['env'] = literal_eval(data['webapp']['env'])
        else:
            data['webapp'] = {}
        if 'addons' in data:
            for addon in data['addons']:
                if ('env' in addon) and (addon['env'] is not None) \
                        and (isinstance(addon['env'], str)) \
                        and (len(addon['env']) > 0):
                    addon['env'] = literal_eval(addon['env'])
        if data['comment'] is None:
            data['comment'] = ""
        return data


class UserSchema(ma.SQLAlchemyAutoSchema):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    class Meta:
        model = User
        sqla_session = db.session

    id = ma.auto_field(dump_only=True)
    public_keys = fields.Nested(
        "SSHKeySchema",
        default=[],
        many=True,
    )
    role = EnumField(RoleEnum, by_value=True)
    created_at = ma.auto_field(dump_only=True)
    updated_at = ma.auto_field(dump_only=True)


class AppTokenSchema(ma.SQLAlchemyAutoSchema):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    class Meta:
        model = AppToken
        sqla_session = db.session

    id = ma.auto_field(dump_only=True)
    created_at = ma.auto_field(dump_only=True)
    updated_at = ma.auto_field(dump_only=True)


class CronSchema(ma.SQLAlchemyAutoSchema):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    class Meta:
        model = Cron
        sqla_session = db.session

    id = ma.auto_field(dump_only=True)
    created_at = ma.auto_field(dump_only=True)
    updated_at = ma.auto_field(dump_only=True)


capsule_input_schema = CapsuleInputSchema()
capsule_output_schema = CapsuleOutputSchema()
capsules_output_schema = CapsuleOutputSchema(many=True)
capsule_verbose_schema = CapsuleSchemaVerbose()
capsules_verbose_schema = CapsuleSchemaVerbose(many=True)
capsule_nats_schema = CapsuleNatsSchema()
runtime_schema = RuntimeSchema()
runtimes_schema = RuntimeSchema(many=True)
sshkey_schema = SSHKeySchema()
sshkeys_schema = SSHKeySchema(many=True)
user_schema = UserSchema()
users_schema = UserSchema(many=True)
webapp_schema = WebAppSchema()
webapp_nats_schema = WebAppNatsSchema()
addon_schema = AddOnSchema()
addons_schema = AddOnSchema(many=True)
apptoken_schema = AppTokenSchema()
apptokens_schema = AppTokenSchema(many=True)
cron_schema = CronSchema()
crons_schema = CronSchema(many=True)
fqdn_schema = FQDNSchema()
