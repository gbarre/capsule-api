"""initial migration

Revision ID: b0e95dfa09d7
Revises: 
Create Date: 2020-06-15 11:27:23.970801

"""
from alembic import op
import sqlalchemy as sa
import models


# revision identifiers, used by Alembic.
revision = 'b0e95dfa09d7'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('runtimes',
    sa.Column('id', models.GUID(), nullable=False),
    sa.Column('name', sa.String(length=256), nullable=False),
    sa.Column('desc', sa.String(length=256), nullable=False),
    sa.Column('fam', sa.String(length=256), nullable=False),
    sa.Column('runtime_type', sa.Enum('webapp', 'addon', name='runtimetypeenum'), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('id')
    )
    op.create_table('users',
    sa.Column('id', models.GUID(), nullable=False),
    sa.Column('name', sa.String(length=32), nullable=False),
    sa.Column('role', sa.Enum('user', 'admin', 'superadmin', name='roleenum'), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('id'),
    sa.UniqueConstraint('name')
    )
    op.create_table('apptokens',
    sa.Column('id', models.GUID(), nullable=False),
    sa.Column('app', sa.String(length=256), nullable=False),
    sa.Column('owner_id', models.GUID(), nullable=True),
    sa.Column('token', sa.String(length=256), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['owner_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('id'),
    sa.UniqueConstraint('token')
    )
    op.create_table('available_options',
    sa.Column('id', models.GUID(), nullable=False),
    sa.Column('runtime_id', models.GUID(), nullable=True),
    sa.Column('access_level', sa.Enum('user', 'admin', 'superadmin', name='roleenum'), nullable=False),
    sa.Column('tag', sa.String(length=256), nullable=False),
    sa.Column('field_name', sa.String(length=256), nullable=False),
    sa.Column('field_description', sa.String(length=256), nullable=True),
    sa.Column('value_type', sa.Enum('integer', 'float', 'boolean', 'string', 'file', name='optionvaluetypeenum'), nullable=False),
    sa.Column('default_value', sa.String(length=256), nullable=True),
    sa.ForeignKeyConstraint(['runtime_id'], ['runtimes.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('id')
    )
    op.create_table('sshkeys',
    sa.Column('id', models.GUID(), nullable=False),
    sa.Column('public_key', sa.Text(), nullable=False),
    sa.Column('user_id', models.GUID(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('id')
    )
    op.create_table('webapps',
    sa.Column('id', models.GUID(), nullable=False),
    sa.Column('runtime_id', models.GUID(), nullable=True),
    sa.Column('tls_redirect_https', sa.Boolean(), nullable=True),
    sa.Column('tls_crt', sa.Text(), nullable=True),
    sa.Column('tls_key', sa.Text(), nullable=True),
    sa.Column('env', sa.Text(), nullable=True),
    sa.Column('quota_volume_size', sa.String(length=256), nullable=True),
    sa.Column('quota_memory_max', sa.String(length=256), nullable=True),
    sa.Column('quota_cpu_max', sa.String(length=256), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['runtime_id'], ['runtimes.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('id')
    )
    op.create_table('available_option_validation_rules',
    sa.Column('id', models.GUID(), nullable=False),
    sa.Column('available_option_id', models.GUID(), nullable=True),
    sa.Column('type', sa.Enum('regex', 'min', 'max', 'eq', 'neq', 'format', name='validationruleenum'), nullable=False),
    sa.Column('arg', sa.String(length=256), nullable=False),
    sa.ForeignKeyConstraint(['available_option_id'], ['available_options.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('id')
    )
    op.create_table('capsules',
    sa.Column('id', models.GUID(), nullable=False),
    sa.Column('uid', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('name', sa.String(length=256), nullable=False),
    sa.Column('webapp_id', models.GUID(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['webapp_id'], ['webapps.id'], ),
    sa.PrimaryKeyConstraint('uid'),
    sa.UniqueConstraint('id'),
    sa.UniqueConstraint('name'),
    sa.UniqueConstraint('uid')
    )
    op.create_table('fqdns',
    sa.Column('id', models.GUID(), nullable=False),
    sa.Column('webapp_id', models.GUID(), nullable=True),
    sa.Column('name', sa.String(length=256), nullable=False),
    sa.Column('alias', sa.Boolean(), nullable=False),
    sa.ForeignKeyConstraint(['webapp_id'], ['webapps.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('id')
    )
    op.create_table('addons',
    sa.Column('id', models.GUID(), nullable=False),
    sa.Column('runtime_id', models.GUID(), nullable=True),
    sa.Column('capsule_id', models.GUID(), nullable=True),
    sa.Column('name', sa.String(length=256), nullable=False),
    sa.Column('description', sa.String(length=256), nullable=True),
    sa.Column('uri', sa.String(length=256), nullable=True),
    sa.Column('env', sa.Text(), nullable=True),
    sa.Column('quota_volume_size', sa.String(length=256), nullable=True),
    sa.Column('quota_memory_max', sa.String(length=256), nullable=True),
    sa.Column('quota_cpu_max', sa.String(length=256), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['capsule_id'], ['capsules.id'], ),
    sa.ForeignKeyConstraint(['runtime_id'], ['runtimes.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('id')
    )
    op.create_table('capsules_sshkeys',
    sa.Column('capsule_id', models.GUID(), nullable=True),
    sa.Column('sshkey_id', models.GUID(), nullable=True),
    sa.ForeignKeyConstraint(['capsule_id'], ['capsules.id'], ),
    sa.ForeignKeyConstraint(['sshkey_id'], ['sshkeys.id'], )
    )
    op.create_table('capsules_users',
    sa.Column('capsule_id', models.GUID(), nullable=True),
    sa.Column('user_id', models.GUID(), nullable=True),
    sa.ForeignKeyConstraint(['capsule_id'], ['capsules.id'], ),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], )
    )
    op.create_table('options',
    sa.Column('id', models.GUID(), nullable=False),
    sa.Column('webapp_id', models.GUID(), nullable=True),
    sa.Column('addon_id', models.GUID(), nullable=True),
    sa.Column('tag', sa.String(length=256), nullable=True),
    sa.Column('field_name', sa.String(length=256), nullable=True),
    sa.Column('value', sa.String(length=256), nullable=True),
    sa.ForeignKeyConstraint(['addon_id'], ['addons.id'], ),
    sa.ForeignKeyConstraint(['webapp_id'], ['webapps.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('options')
    op.drop_table('capsules_users')
    op.drop_table('capsules_sshkeys')
    op.drop_table('addons')
    op.drop_table('fqdns')
    op.drop_table('capsules')
    op.drop_table('available_option_validation_rules')
    op.drop_table('webapps')
    op.drop_table('sshkeys')
    op.drop_table('available_options')
    op.drop_table('apptokens')
    op.drop_table('users')
    op.drop_table('runtimes')
    # ### end Alembic commands ###