"""add webapp volume size

Revision ID: 145a3fd851e3
Revises: 566cfbfc6342
Create Date: 2021-04-06 15:40:24.086622

"""
from alembic import op
import sqlalchemy as sa
import models


# revision identifiers, used by Alembic.
revision = '145a3fd851e3'
down_revision = '566cfbfc6342'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('webapps', sa.Column('volume_size', sa.Integer(), nullable=False, server_default='10'))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('webapps', 'volume_size')
    # ### end Alembic commands ###
