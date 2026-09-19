-- consent_required keeps the values the backfill set: see the up migration for why.
ALTER TABLE clients DROP COLUMN created_via_dcr;
