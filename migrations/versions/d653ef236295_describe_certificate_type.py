"""describe certificate type

Revision ID: d653ef236295
Revises: 0a14fadf7be6
Create Date: 2021-07-16 09:39:28.442230

"""
from alembic import op
import sqlalchemy as sa
import models
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = 'd653ef236295'
down_revision = '0a14fadf7be6'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('capsules', sa.Column('certificate', sa.Enum('none', 'acme', 'manual', name='certificateenum'), nullable=False))
    op.drop_column('capsules', 'acme_certificate')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('capsules', sa.Column('acme_certificate', mysql.TINYINT(display_width=1), autoincrement=False, nullable=False))
    op.drop_column('capsules', 'certificate')
    # ### end Alembic commands ###