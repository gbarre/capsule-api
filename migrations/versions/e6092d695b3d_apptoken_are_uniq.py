"""apptoken are uniq

Revision ID: e6092d695b3d
Revises: 2d907ff68cad
Create Date: 2020-06-05 11:09:53.292893

"""
from alembic import op
import sqlalchemy as sa
import models


# revision identifiers, used by Alembic.
revision = 'e6092d695b3d'
down_revision = '2d907ff68cad'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_unique_constraint(None, 'apptokens', ['token'])
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint(None, 'apptokens', type_='unique')
    # ### end Alembic commands ###
