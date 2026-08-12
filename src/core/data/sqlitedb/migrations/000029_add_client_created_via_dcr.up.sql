-- Self-registered clients require consent (#108).
--
-- created_via_dcr records that a client registered itself through /connect/register
-- rather than being created by an administrator. It is the enforced form of what the
-- dcr_ identifier prefix only suggests: an administrator can name a client
-- "dcr_anything", so the prefix cannot be trusted as a provenance test. Everything
-- that asks "did this client vouch for itself" reads this column instead.
--
-- The backfill sets consent_required as well as the marker, and that is deliberate.
-- Every client that registered itself before this migration was stamped
-- ConsentRequired: false at creation, so without the backfill those clients keep
-- issuing codes with no consent screen forever, in exactly the deployments that
-- enabled dynamic registration. A forward-looking-only fix would leave the defect
-- standing where it has already been exploited.
--
-- The prefix is a sound signal in one direction only. Every client created through
-- /connect/register has carried it since the feature shipped, so there are no false
-- negatives. The one error it can make is a false positive, an administrator who
-- named a client dcr_something by hand, and that costs one unnecessary consent
-- screen which the per-client consent toggle in the admin console turns off.
--
-- ESCAPE '!' , never ESCAPE '\' : the backslash escapes the closing quote inside a
-- MySQL string literal, so that spelling is a syntax error on MySQL and parses fine
-- on the other three, which is how it would reach a release. Without any escape at
-- all, `_` is a single-character wildcard and LIKE 'dcr_%' also matches "dcrX9999"
-- on all four engines. Both confirmed by running them on all four.
--
-- The down migration drops the column and leaves consent_required as this backfill
-- set it. The reverse direction is "make these clients silently grantable again",
-- which is the defect, so the loss is accepted rather than worked around.
ALTER TABLE clients ADD COLUMN created_via_dcr numeric NOT NULL DEFAULT 0;

UPDATE clients SET created_via_dcr = 1, consent_required = 1
 WHERE client_identifier LIKE 'dcr!_%' ESCAPE '!';
