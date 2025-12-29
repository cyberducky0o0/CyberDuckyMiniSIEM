#!/usr/bin/env python3
"""
Run all pending migrations in order
"""
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import create_app
from app.extensions import db
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def table_exists(table_name):
    """Check if a table exists"""
    result = db.session.execute(db.text("""
        SELECT EXISTS (
            SELECT FROM information_schema.tables 
            WHERE table_name = :table_name
        )
    """), {'table_name': table_name})
    return result.scalar()

def column_exists(table_name, column_name):
    """Check if a column exists in a table"""
    result = db.session.execute(db.text("""
        SELECT EXISTS (
            SELECT FROM information_schema.columns 
            WHERE table_name = :table_name 
            AND column_name = :column_name
        )
    """), {'table_name': table_name, 'column_name': column_name})
    return result.scalar()

def run_migration_file(migration_file):
    """Run a single migration file"""
    logger.info(f"Running migration: {os.path.basename(migration_file)}")

    with open(migration_file, 'r') as f:
        sql = f.read()

    # Remove comments
    lines = []
    for line in sql.split('\n'):
        if not line.strip().startswith('--'):
            lines.append(line)
    sql = '\n'.join(lines)

    # Split by $$ blocks (for DO blocks) or semicolons
    statements = []
    current_statement = []
    in_do_block = False

    for line in sql.split('\n'):
        if '$$' in line:
            in_do_block = not in_do_block
            current_statement.append(line)
            if not in_do_block and ';' in line:
                # End of DO block
                statements.append('\n'.join(current_statement))
                current_statement = []
        elif in_do_block:
            current_statement.append(line)
        elif ';' in line:
            current_statement.append(line)
            statements.append('\n'.join(current_statement))
            current_statement = []
        elif line.strip():
            current_statement.append(line)

    # Execute each statement
    for statement in statements:
        statement = statement.strip()
        if statement and not statement.lower().startswith('select'):
            logger.info(f"  Executing: {statement[:80]}...")
            try:
                db.session.execute(db.text(statement))
            except Exception as e:
                # If it's an "already exists" error, that's okay
                if 'already exists' in str(e).lower() or 'duplicate' in str(e).lower():
                    logger.info(f"    Skipping (already exists): {str(e)[:100]}")
                else:
                    raise

    db.session.commit()
    logger.info(f"Migration completed: {os.path.basename(migration_file)}")

def run_all_migrations():
    """Run all migrations"""
    app = create_app('development')
    
    with app.app_context():
        try:
            logger.info("="*80)
            logger.info("Starting database migrations")
            logger.info("="*80)
            
            migrations_dir = os.path.join(os.path.dirname(__file__), '..', 'migrations')
            
            # Migration order
            migrations = [
                'add_normalized_events.sql',
                'add_normalized_event_id_to_anomalies.sql'
            ]
            
            # Check current state
            logger.info("\nChecking current database state...")
            normalized_events_exists = table_exists('normalized_events')
            normalized_event_id_exists = column_exists('anomalies', 'normalized_event_id')
            
            logger.info(f"  - normalized_events table exists: {normalized_events_exists}")
            logger.info(f"  - anomalies.normalized_event_id column exists: {normalized_event_id_exists}")
            
            # Run migrations
            logger.info("\nRunning migrations...")
            for migration_file in migrations:
                migration_path = os.path.join(migrations_dir, migration_file)
                
                if not os.path.exists(migration_path):
                    logger.warning(f"  Migration file not found: {migration_file}")
                    continue
                
                # Check if migration is needed
                if migration_file == 'add_normalized_events.sql' and normalized_events_exists:
                    logger.info(f"Skipping {migration_file} (table already exists)")
                    continue

                if migration_file == 'add_normalized_event_id_to_anomalies.sql' and normalized_event_id_exists:
                    logger.info(f"Skipping {migration_file} (column already exists)")
                    continue
                
                run_migration_file(migration_path)
            
            # Verify final state
            logger.info("\n" + "="*80)
            logger.info("Verifying database state...")
            logger.info("="*80)
            
            # Check normalized_events table
            if table_exists('normalized_events'):
                result = db.session.execute(db.text("""
                    SELECT COUNT(*) FROM information_schema.columns
                    WHERE table_name = 'normalized_events'
                """))
                col_count = result.scalar()
                logger.info(f"normalized_events table exists with {col_count} columns")
            else:
                logger.error("normalized_events table does not exist!")
                return False

            # Check normalized_event_id column
            if column_exists('anomalies', 'normalized_event_id'):
                result = db.session.execute(db.text("""
                    SELECT data_type, is_nullable
                    FROM information_schema.columns
                    WHERE table_name = 'anomalies'
                    AND column_name = 'normalized_event_id'
                """))
                row = result.fetchone()
                logger.info(f"anomalies.normalized_event_id column exists")
                logger.info(f"   - Type: {row[0]}")
                logger.info(f"   - Nullable: {row[1]}")
            else:
                logger.error("anomalies.normalized_event_id column does not exist!")
                return False

            logger.info("\n" + "="*80)
            logger.info("ALL MIGRATIONS COMPLETED SUCCESSFULLY!")
            logger.info("="*80)
            
            return True
            
        except Exception as e:
            logger.error(f"\nMigration failed: {e}")
            import traceback
            traceback.print_exc()
            db.session.rollback()
            return False

if __name__ == '__main__':
    success = run_all_migrations()
    sys.exit(0 if success else 1)

