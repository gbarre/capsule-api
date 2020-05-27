"""env text

Revision ID: 3dcfe0af20a5
Revises: 015035db7ede
Create Date: 2020-05-27 16:09:22.624163

"""
from alembic import op
import sqlalchemy as sa
import models
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = '3dcfe0af20a5'
down_revision = '015035db7ede'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.alter_column('addons', 'env',
               existing_type=mysql.VARCHAR(length=256),
               type_=sa.Text(),
               existing_nullable=True)
    op.alter_column('webapps', 'env',
               existing_type=mysql.VARCHAR(length=256),
               type_=sa.Text(),
               existing_nullable=True)
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.alter_column('webapps', 'env',
               existing_type=sa.Text(),
               type_=mysql.VARCHAR(length=256),
               existing_nullable=True)
    op.alter_column('addons', 'env',
               existing_type=sa.Text(),
               type_=mysql.VARCHAR(length=256),
               existing_nullable=True)
    # ### end Alembic commands ###
