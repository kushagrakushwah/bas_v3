"""Initial schema

Revision ID: 94188141ef93
Revises: 
Create Date: 2026-07-02 13:40:58.447168

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '94188141ef93'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table('events',
    sa.Column('id', sa.String(), nullable=False),
    sa.Column('event_type', sa.String(), nullable=True),
    sa.Column('payload', sa.JSON(), nullable=True),
    sa.Column('timestamp', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    
    op.create_table('integrations',
    sa.Column('id', sa.String(), nullable=False),
    sa.Column('name', sa.String(), nullable=True),
    sa.Column('type', sa.String(), nullable=True),
    sa.Column('target', sa.String(), nullable=True),
    sa.Column('status', sa.String(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    
    op.create_table('simulations',
    sa.Column('id', sa.String(), nullable=False),
    sa.Column('name', sa.String(), nullable=True),
    sa.Column('target', sa.String(), nullable=True),
    sa.Column('status', sa.String(), nullable=True),
    sa.Column('created_by', sa.String(), nullable=True),
    sa.Column('metadata_json', sa.JSON(), nullable=True),
    sa.Column('modules', sa.JSON(), nullable=True),
    sa.Column('detection_summary', sa.JSON(), nullable=True),
    sa.Column('soc_score', sa.Float(), nullable=True),
    sa.Column('coverage_data', sa.JSON(), nullable=True),
    sa.Column('blindspot_data', sa.JSON(), nullable=True),
    sa.Column('sigma_rules', sa.JSON(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=True),
    sa.Column('started_at', sa.DateTime(), nullable=True),
    sa.Column('finished_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_simulations_created_at'), 'simulations', ['created_at'], unique=False)
    op.create_index(op.f('ix_simulations_status'), 'simulations', ['status'], unique=False)
    
    op.create_table('module_results',
    sa.Column('id', sa.String(), nullable=False),
    sa.Column('simulation_id', sa.String(), nullable=True),
    sa.Column('module', sa.String(), nullable=True),
    sa.Column('status', sa.String(), nullable=True),
    sa.Column('error', sa.Text(), nullable=True),
    sa.Column('stats', sa.JSON(), nullable=True),
    sa.Column('started_at', sa.DateTime(), nullable=True),
    sa.Column('finished_at', sa.DateTime(), nullable=True),
    sa.Column('duration_s', sa.Float(), nullable=True),
    sa.ForeignKeyConstraint(['simulation_id'], ['simulations.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    
    op.create_table('findings',
    sa.Column('id', sa.String(), nullable=False),
    sa.Column('module_result_id', sa.String(), nullable=True),
    sa.Column('title', sa.String(), nullable=True),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('severity', sa.String(), nullable=True),
    sa.Column('mitre_id', sa.String(), nullable=True),
    sa.Column('evidence', sa.Text(), nullable=True),
    sa.Column('remediation', sa.Text(), nullable=True),
    sa.Column('raw_data', sa.JSON(), nullable=True),
    sa.Column('timestamp', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['module_result_id'], ['module_results.id'], ),
    sa.PrimaryKeyConstraint('id')
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table('findings')
    op.drop_table('module_results')
    op.drop_index(op.f('ix_simulations_status'), table_name='simulations')
    op.drop_index(op.f('ix_simulations_created_at'), table_name='simulations')
    op.drop_table('simulations')
    op.drop_table('integrations')
    op.drop_table('events')
