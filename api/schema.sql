CREATE TABLE IF NOT EXISTS visits (
  id UUID PRIMARY KEY,
  vendor_name TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS uniq_vendor_name
  ON visits (LOWER(vendor_name));

CREATE TABLE IF NOT EXISTS server_challenges (
  id UUID PRIMARY KEY,
  nonce TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  used_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS visit_events (
  id UUID PRIMARY KEY,
  visit_id UUID NOT NULL REFERENCES visits(id),
  event_type TEXT NOT NULL CHECK (event_type IN ('CHECK_IN','CHECK_OUT')),
  vendor_name TEXT NOT NULL,
  latitude DOUBLE PRECISION NOT NULL,
  longitude DOUBLE PRECISION NOT NULL,
  accuracy_meters DOUBLE PRECISION NOT NULL,
  captured_at TIMESTAMPTZ NOT NULL,

  photo_url TEXT NOT NULL,
  photo_sha256 TEXT NOT NULL,

  device_public_key TEXT NOT NULL,
  device_signature TEXT NOT NULL,

  server_challenge_id UUID NOT NULL REFERENCES server_challenges(id),

  user_agent TEXT,
  ip_address TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS uniq_one_checkin_per_visit
  ON visit_events(visit_id) WHERE event_type='CHECK_IN';

CREATE UNIQUE INDEX IF NOT EXISTS uniq_one_checkout_per_visit
  ON visit_events(visit_id) WHERE event_type='CHECK_OUT';

CREATE INDEX IF NOT EXISTS idx_visit_events_time
  ON visit_events(captured_at DESC);