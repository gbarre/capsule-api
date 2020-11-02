"""Add no_reboot flag on capsule

Revision ID: dfcd394b38f3
Revises: a441515c9fd0
Create Date: 2020-10-15 13:44:07.204874

"""
from alembic import op
import sqlalchemy as sa
import models


# revision identifiers, used by Alembic.
revision = 'dfcd394b38f3'
down_revision = 'a441515c9fd0'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('capsules', sa.Column('no_update', sa.Boolean(), nullable=False))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('capsules', 'no_update')
    # ### end Alembic commands ###