#!/usr/bin/env python3
"""
Run migration to add normalized_event_id to anomalies table
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

def run_migration():
    """Run the migration"""
    app = create_app('development')
    
    with app.app_context():
        try:
            logger.info("Starting migration: Add normalized_event_id to anomalies table")
            
            # Read migration SQL
            migration_file = os.path.join(
                os.path.dirname(__file__), 
                '..', 
                'migrations', 
                'add_normalized_event_id_to_anomalies.sql'
            )
            
            with open(migration_file, 'r') as f:
                sql = f.read()
            
            # Execute migration
            logger.info("Executing migration SQL...")
            
            # Split by semicolon and execute each statement
            statements = [s.strip() for s in sql.split(';') if s.strip() and not s.strip().startswith('--')]
            
            for statement in statements:
                if statement:
                    logger.info(f"Executing: {statement[:100]}...")
                    db.session.execute(db.text(statement))
            
            db.session.commit()
            logger.info("✅ Migration completed successfully!")
            
            # Verify the column exists
            result = db.session.execute(db.text("""
                SELECT column_name, data_type, is_nullable 
                FROM information_schema.columns 
                WHERE table_name = 'anomalies' 
                AND column_name = 'normalized_event_id'
            """))
            
            row = result.fetchone()
            if row:
                logger.info(f"✅ Verified: Column 'normalized_event_id' exists")
                logger.info(f"   - Type: {row[1]}")
                logger.info(f"   - Nullable: {row[2]}")
            else:
                logger.error("❌ Column 'normalized_event_id' not found after migration!")
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Migration failed: {e}")
            db.session.rollback()
            return False

if __name__ == '__main__':
    success = run_migration()
    sys.exit(0 if success else 1)

