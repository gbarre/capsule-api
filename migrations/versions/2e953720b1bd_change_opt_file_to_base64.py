"""change opt file to base64

Revision ID: 2e953720b1bd
Revises: dfcd394b38f3
Create Date: 2020-11-16 17:05:35.231715

"""
from alembic import op
import sqlalchemy as sa
import models
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = '2e953720b1bd'
down_revision = 'dfcd394b38f3'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.alter_column('available_options', 'value_type',
               existing_type=mysql.ENUM('integer', 'float', 'boolean', 'string', 'file', collation='utf8_unicode_ci'),
               type_=sa.Enum('integer', 'float', 'boolean', 'string', 'base64', name='optionvaluetypeenum'),
               existing_nullable=False)
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.alter_column('available_options', 'value_type',
               existing_type=sa.Enum('integer', 'float', 'boolean', 'string', 'base64', name='optionvaluetypeenum'),
               type_=mysql.ENUM('integer', 'float', 'boolean', 'string', 'file', collation='utf8_unicode_ci'),
               existing_nullable=False)
    # ### end Alembic commands ###
