-- Phase 2: Heartbeat & Presence - Schema Updates
-- Adds timestamp fields to track device activity and connection status

-- Add last_seen_at and disconnected_at columns to devices table
ALTER TABLE public.devices
ADD COLUMN IF NOT EXISTS last_seen_at timestamp with time zone DEFAULT now(),
ADD COLUMN IF NOT EXISTS disconnected_at timestamp with time zone;

-- Create an index on last_seen_at for efficient queries
CREATE INDEX IF NOT EXISTS idx_devices_last_seen_at ON public.devices(last_seen_at DESC);

-- Create an index on is_active for quick filtering of connected devices
CREATE INDEX IF NOT EXISTS idx_devices_is_active ON public.devices(is_active);

-- Optional: Add a trigger to automatically set last_seen_at when the row is updated
-- This ensures last_seen_at is always accurate even if client doesn't explicitly set it
CREATE OR REPLACE FUNCTION public.update_last_seen_at()
RETURNS TRIGGER AS $$
BEGIN
  IF NEW.is_active = true THEN
    NEW.last_seen_at = now();
    NEW.disconnected_at = NULL;
  ELSIF NEW.is_active = false AND OLD.is_active = true THEN
    -- Device was just marked as inactive
    NEW.disconnected_at = now();
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create the trigger if it doesn't exist
DROP TRIGGER IF EXISTS trigger_update_last_seen_at ON public.devices;
CREATE TRIGGER trigger_update_last_seen_at
  BEFORE UPDATE ON public.devices
  FOR EACH ROW
  EXECUTE FUNCTION public.update_last_seen_at();

-- Phase 1: HIK rotation support - track hik_version per device
ALTER TABLE public.devices
ADD COLUMN IF NOT EXISTS hik_version integer DEFAULT 0;

-- Phase 3: Fix Connections table - add status column and timestamp
ALTER TABLE public.connections
ADD COLUMN IF NOT EXISTS status text DEFAULT 'pending' CHECK (status IN ('pending', 'accepted', 'rejected')),
ADD COLUMN IF NOT EXISTS created_at timestamp with time zone DEFAULT now();

CREATE INDEX IF NOT EXISTS idx_connections_status ON public.connections(status);
CREATE INDEX IF NOT EXISTS idx_connections_user_ids ON public.connections(initiator_user_id, target_user_id);

-- Verify the schema
-- SELECT table_name, column_name, data_type
-- FROM information_schema.columns
-- WHERE table_name = 'devices';
