"""Fix typo

Revision ID: 0aab867e4b3b
Revises: 87bc886d7a3c
Create Date: 2020-04-30 17:47:57.892763

"""
from alembic import op
import sqlalchemy as sa
import models
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = '0aab867e4b3b'
down_revision = '87bc886d7a3c'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.alter_column('sshkeys', 'public_key',
               existing_type=mysql.TEXT(),
               type_=sa.String(length=256),
               existing_nullable=False)
    op.create_unique_constraint(None, 'sshkeys', ['public_key'])
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint(None, 'sshkeys', type_='unique')
    op.alter_column('sshkeys', 'public_key',
               existing_type=sa.String(length=256),
               type_=mysql.TEXT(),
               existing_nullable=False)
    # ### end Alembic commands ###
