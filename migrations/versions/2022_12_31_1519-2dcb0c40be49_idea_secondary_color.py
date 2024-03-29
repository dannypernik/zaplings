"""idea.secondary_color

Revision ID: 2dcb0c40be49
Revises: a2afa1281e72
Create Date: 2022-12-31 15:19:04.283682

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '2dcb0c40be49'
down_revision = 'a2afa1281e72'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('idea', schema=None) as batch_op:
        batch_op.add_column(sa.Column('secondary_color', sa.String(length=24), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('idea', schema=None) as batch_op:
        batch_op.drop_column('secondary_color')

    # ### end Alembic commands ###
