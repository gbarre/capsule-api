"""quota can be null

Revision ID: fd6aeb830fad
Revises: eda798970d46
Create Date: 2020-05-28 17:32:01.547352

"""
from alembic import op
import sqlalchemy as sa
import models
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = 'fd6aeb830fad'
down_revision = 'eda798970d46'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.alter_column('addons', 'quota_cpu_max',
               existing_type=mysql.VARCHAR(length=256),
               nullable=True)
    op.alter_column('addons', 'quota_memory_max',
               existing_type=mysql.VARCHAR(length=256),
               nullable=True)
    op.alter_column('addons', 'quota_volume_size',
               existing_type=mysql.VARCHAR(length=256),
               nullable=True)
    op.alter_column('webapps', 'quota_cpu_max',
               existing_type=mysql.VARCHAR(length=256),
               nullable=True)
    op.alter_column('webapps', 'quota_memory_max',
               existing_type=mysql.VARCHAR(length=256),
               nullable=True)
    op.alter_column('webapps', 'quota_volume_size',
               existing_type=mysql.VARCHAR(length=256),
               nullable=True)
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.alter_column('webapps', 'quota_volume_size',
               existing_type=mysql.VARCHAR(length=256),
               nullable=False)
    op.alter_column('webapps', 'quota_memory_max',
               existing_type=mysql.VARCHAR(length=256),
               nullable=False)
    op.alter_column('webapps', 'quota_cpu_max',
               existing_type=mysql.VARCHAR(length=256),
               nullable=False)
    op.alter_column('addons', 'quota_volume_size',
               existing_type=mysql.VARCHAR(length=256),
               nullable=False)
    op.alter_column('addons', 'quota_memory_max',
               existing_type=mysql.VARCHAR(length=256),
               nullable=False)
    op.alter_column('addons', 'quota_cpu_max',
               existing_type=mysql.VARCHAR(length=256),
               nullable=False)
    # ### end Alembic commands ###