"""add comment to capsule


Revision ID: 8be9199174bf
Revises: 47039cab374c
Create Date: 2021-01-25 16:16:42.782270

"""
from alembic import op
import sqlalchemy as sa
import models


# revision identifiers, used by Alembic.
revision = '8be9199174bf'
down_revision = '47039cab374c'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('capsules', sa.Column('comment', sa.Text(), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('capsules', 'comment')
    # ### end Alembic commands ###
