"""no fqdn unicity check

Revision ID: 5ec5c4025cea
Revises: fd6aeb830fad
Create Date: 2020-05-29 09:22:22.098467

"""
from alembic import op
import sqlalchemy as sa
import models


# revision identifiers, used by Alembic.
revision = '5ec5c4025cea'
down_revision = 'fd6aeb830fad'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_index('name', table_name='fqdns')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_index('name', 'fqdns', ['name'], unique=True)
    # ### end Alembic commands ###
