"""create/update for app token

Revision ID: 2d907ff68cad
Revises: c893ec7b7475
Create Date: 2020-06-04 14:32:42.136211

"""
from alembic import op
import sqlalchemy as sa
import models


# revision identifiers, used by Alembic.
revision = '2d907ff68cad'
down_revision = 'c893ec7b7475'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('apptokens', sa.Column('created_at', sa.DateTime(), nullable=True))
    op.add_column('apptokens', sa.Column('updated_at', sa.DateTime(), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('apptokens', 'updated_at')
    op.drop_column('apptokens', 'created_at')
    # ### end Alembic commands ###