-- Migration: Add normalized_event_id column to anomalies table
-- Date: 2025-11-01
-- Description: Add support for linking anomalies to normalized events

-- Add normalized_event_id column (without constraint first)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'anomalies'
        AND column_name = 'normalized_event_id'
    ) THEN
        ALTER TABLE anomalies ADD COLUMN normalized_event_id VARCHAR(36);
        RAISE NOTICE 'Column normalized_event_id added to anomalies table';
    ELSE
        RAISE NOTICE 'Column normalized_event_id already exists in anomalies table';
    END IF;
END $$;

-- Add index for performance
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_indexes
        WHERE tablename = 'anomalies'
        AND indexname = 'idx_anomalies_normalized_event_id'
    ) THEN
        CREATE INDEX idx_anomalies_normalized_event_id ON anomalies(normalized_event_id);
        RAISE NOTICE 'Index idx_anomalies_normalized_event_id created';
    ELSE
        RAISE NOTICE 'Index idx_anomalies_normalized_event_id already exists';
    END IF;
END $$;

-- Add foreign key constraint (only if normalized_events table exists)
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_name = 'normalized_events'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE constraint_name = 'fk_anomalies_normalized_event_id'
    ) THEN
        ALTER TABLE anomalies
        ADD CONSTRAINT fk_anomalies_normalized_event_id
        FOREIGN KEY (normalized_event_id)
        REFERENCES normalized_events(id)
        ON DELETE CASCADE;
        RAISE NOTICE 'Foreign key constraint fk_anomalies_normalized_event_id added';
    ELSE
        RAISE NOTICE 'Foreign key constraint fk_anomalies_normalized_event_id already exists or normalized_events table does not exist';
    END IF;
END $$;

