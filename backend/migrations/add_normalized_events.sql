-- Migration: Add normalized_events table and update anomalies table
-- Purpose: Enable multi-source log analysis with normalized schema
-- Date: 2025-10-31

-- Add normalized_event_id column to anomalies table (nullable for backward compatibility)
ALTER TABLE anomalies 
ADD COLUMN IF NOT EXISTS normalized_event_id VARCHAR(36);

-- Make log_entry_id nullable (since anomalies can now link to either log_entry or normalized_event)
ALTER TABLE anomalies 
ALTER COLUMN log_entry_id DROP NOT NULL;

-- Add foreign key constraint
ALTER TABLE anomalies
ADD CONSTRAINT fk_anomalies_normalized_event
FOREIGN KEY (normalized_event_id) REFERENCES normalized_events(id) ON DELETE CASCADE;

-- Add index for normalized_event_id
CREATE INDEX IF NOT EXISTS idx_anomalies_normalized_event_id ON anomalies(normalized_event_id);

-- Note: The normalized_events table will be created automatically by SQLAlchemy
-- when the application starts, using the NormalizedEventModel definition.
-- This migration only handles the anomalies table updates.

