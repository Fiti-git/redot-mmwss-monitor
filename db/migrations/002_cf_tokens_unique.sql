-- 002: Make cf_tokens.label UNIQUE so upserts actually work.
-- Slice 1 shipped without this, then the collector restart-looped and inserted
-- a duplicate cf_tokens row each cycle. Dedupe first, then constrain.

BEGIN;

-- 1. Remap any zones pointing at a duplicate token to the canonical (oldest) one for that label.
UPDATE mmwss.zones z
SET cf_token_id = (
    SELECT MIN(t2.id) FROM mmwss.cf_tokens t2
    WHERE t2.label = (SELECT t1.label FROM mmwss.cf_tokens t1 WHERE t1.id = z.cf_token_id)
);

-- 2. Delete duplicate token rows, keep the oldest per label.
DELETE FROM mmwss.cf_tokens
WHERE id NOT IN (SELECT MIN(id) FROM mmwss.cf_tokens GROUP BY label);

-- 3. Enforce uniqueness from now on.
ALTER TABLE mmwss.cf_tokens
    ADD CONSTRAINT cf_tokens_label_unique UNIQUE (label);

COMMIT;
