CREATE TABLE IF NOT EXISTS observations (
  seq BIGSERIAL PRIMARY KEY,
  event_id TEXT UNIQUE NOT NULL,
  feed_source TEXT NOT NULL,
  upstream_idx NUMERIC(20,0),
  source_ts TIMESTAMPTZ,
  received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  action TEXT NOT NULL,
  threat_type TEXT NOT NULL,
  indicator TEXT,
  indicator_ip INET,
  raw_payload JSONB NOT NULL,
  country_code TEXT,
  asn BIGINT,
  enrichment_source TEXT,
  assessment JSONB,
  UNIQUE (feed_source, upstream_idx)
);
CREATE INDEX IF NOT EXISTS obs_recent ON observations(received_at DESC);
CREATE TABLE IF NOT EXISTS feed_state (
  feed_source TEXT PRIMARY KEY,
  state TEXT NOT NULL DEFAULT 'unknown',
  last_idx NUMERIC(20,0),
  last_event_at TIMESTAMPTZ,
  last_received_at TIMESTAMPTZ,
  last_success_at TIMESTAMPTZ,
  last_attempt_at TIMESTAMPTZ,
  last_error TEXT,
  gap_count INTEGER NOT NULL DEFAULT 0,
  degraded_reason TEXT
);
CREATE TABLE IF NOT EXISTS coverage_gaps (
  id BIGSERIAL PRIMARY KEY,
  feed_source TEXT NOT NULL,
  first_idx NUMERIC(20,0),
  last_idx NUMERIC(20,0),
  observed_at TIMESTAMPTZ DEFAULT now(),
  reason TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS reference_datasets (
  source TEXT PRIMARY KEY,
  fetched_at TIMESTAMPTZ NOT NULL,
  source_date TEXT,
  payload JSONB NOT NULL
);
