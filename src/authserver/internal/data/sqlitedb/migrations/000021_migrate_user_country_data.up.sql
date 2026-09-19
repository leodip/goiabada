-- Migration 000021: migrate stored user country data to the datahub dataset.
--
-- Chunk 3 of the biter777 -> generated core/countries migration. The calling
-- codes for 17 territories changed and two countries (AN, YU) were dropped, so
-- persisted phone-country and address-country values must be migrated.
--
-- This is a data-only migration (SQLite). Statements are DISJOINT and
-- WHERE-guarded on the ORIGINAL (uniqueid, callingcode), so classification
-- always reads original values (no CASE that both reads and writes a column --
-- avoids MySQL's left-to-right SET assignment hazard), and the whole file is
-- idempotent / restart-safe: a transformed row no longer matches any old-code
-- guard, so re-running cannot re-prepend, re-invalidate, or reintroduce a _1 id.
--
-- Phone verification is PRESERVED only where the effective E.164 number is
-- unchanged: prefix transforms (old-code digits moved into phone_number) and
-- canonical-code identifier-only remaps. It is invalidated otherwise.

-- Removed phone countries (AN/ANT, YU/YUG): clear the country + code,
-- retain the local phone_number, and drop any verification state.
UPDATE users SET
  phone_number_country_uniqueid = '',
  phone_number_country_callingcode = '',
  phone_number_verified = 0,
  phone_number_verification_code_encrypted = NULL,
  phone_number_verification_code_issued_at = NULL
WHERE phone_number_country_uniqueid IN ('ANT_0', 'YUG_0');

-- Prefix transforms: the new calling code is a prefix of the old one, so
-- the removed leading digits move into phone_number and the full E.164
-- number (and its verified state) is preserved -- when it still fits.
-- Oversized or empty numbers cannot be preserved and are re-verified.
UPDATE users SET
  phone_number = '18' || phone_number,
  phone_number_country_uniqueid = 'ALA_0',
  phone_number_country_callingcode = '+358'
WHERE phone_number_country_uniqueid = 'ALA_0'
  AND phone_number_country_callingcode = '+35818'
  AND phone_number IS NOT NULL AND phone_number <> ''
  AND LENGTH(phone_number) <= 28;
UPDATE users SET
  phone_number_country_uniqueid = 'ALA_0',
  phone_number_country_callingcode = '+358',
  phone_number_verified = 0,
  phone_number_verification_code_encrypted = NULL,
  phone_number_verification_code_issued_at = NULL
WHERE phone_number_country_uniqueid = 'ALA_0'
  AND phone_number_country_callingcode = '+35818'
  AND (phone_number IS NULL OR phone_number = '' OR LENGTH(phone_number) > 28);

UPDATE users SET
  phone_number = '3' || phone_number,
  phone_number_country_uniqueid = 'BES_0',
  phone_number_country_callingcode = '+599'
WHERE phone_number_country_uniqueid = 'BES_0'
  AND phone_number_country_callingcode = '+5993'
  AND phone_number IS NOT NULL AND phone_number <> ''
  AND LENGTH(phone_number) <= 29;
UPDATE users SET
  phone_number_country_uniqueid = 'BES_0',
  phone_number_country_callingcode = '+599',
  phone_number_verified = 0,
  phone_number_verification_code_encrypted = NULL,
  phone_number_verification_code_issued_at = NULL
WHERE phone_number_country_uniqueid = 'BES_0'
  AND phone_number_country_callingcode = '+5993'
  AND (phone_number IS NULL OR phone_number = '' OR LENGTH(phone_number) > 29);

UPDATE users SET
  phone_number = '4' || phone_number,
  phone_number_country_uniqueid = 'BES_0',
  phone_number_country_callingcode = '+599'
WHERE phone_number_country_uniqueid = 'BES_1'
  AND phone_number_country_callingcode = '+5994'
  AND phone_number IS NOT NULL AND phone_number <> ''
  AND LENGTH(phone_number) <= 29;
UPDATE users SET
  phone_number_country_uniqueid = 'BES_0',
  phone_number_country_callingcode = '+599',
  phone_number_verified = 0,
  phone_number_verification_code_encrypted = NULL,
  phone_number_verification_code_issued_at = NULL
WHERE phone_number_country_uniqueid = 'BES_1'
  AND phone_number_country_callingcode = '+5994'
  AND (phone_number IS NULL OR phone_number = '' OR LENGTH(phone_number) > 29);

UPDATE users SET
  phone_number = '89162' || phone_number,
  phone_number_country_uniqueid = 'CCK_0',
  phone_number_country_callingcode = '+61'
WHERE phone_number_country_uniqueid = 'CCK_1'
  AND phone_number_country_callingcode = '+6189162'
  AND phone_number IS NOT NULL AND phone_number <> ''
  AND LENGTH(phone_number) <= 25;
UPDATE users SET
  phone_number_country_uniqueid = 'CCK_0',
  phone_number_country_callingcode = '+61',
  phone_number_verified = 0,
  phone_number_verification_code_encrypted = NULL,
  phone_number_verification_code_issued_at = NULL
WHERE phone_number_country_uniqueid = 'CCK_1'
  AND phone_number_country_callingcode = '+6189162'
  AND (phone_number IS NULL OR phone_number = '' OR LENGTH(phone_number) > 25);

UPDATE users SET
  phone_number = '9' || phone_number,
  phone_number_country_uniqueid = 'CUW_0',
  phone_number_country_callingcode = '+599'
WHERE phone_number_country_uniqueid = 'CUW_0'
  AND phone_number_country_callingcode = '+5999'
  AND phone_number IS NOT NULL AND phone_number <> ''
  AND LENGTH(phone_number) <= 29;
UPDATE users SET
  phone_number_country_uniqueid = 'CUW_0',
  phone_number_country_callingcode = '+599',
  phone_number_verified = 0,
  phone_number_verification_code_encrypted = NULL,
  phone_number_verification_code_issued_at = NULL
WHERE phone_number_country_uniqueid = 'CUW_0'
  AND phone_number_country_callingcode = '+5999'
  AND (phone_number IS NULL OR phone_number = '' OR LENGTH(phone_number) > 29);

UPDATE users SET
  phone_number = '89164' || phone_number,
  phone_number_country_uniqueid = 'CXR_0',
  phone_number_country_callingcode = '+61'
WHERE phone_number_country_uniqueid = 'CXR_0'
  AND phone_number_country_callingcode = '+6189164'
  AND phone_number IS NOT NULL AND phone_number <> ''
  AND LENGTH(phone_number) <= 25;
UPDATE users SET
  phone_number_country_uniqueid = 'CXR_0',
  phone_number_country_callingcode = '+61',
  phone_number_verified = 0,
  phone_number_verification_code_encrypted = NULL,
  phone_number_verification_code_issued_at = NULL
WHERE phone_number_country_uniqueid = 'CXR_0'
  AND phone_number_country_callingcode = '+6189164'
  AND (phone_number IS NULL OR phone_number = '' OR LENGTH(phone_number) > 25);

UPDATE users SET
  phone_number = '1481' || phone_number,
  phone_number_country_uniqueid = 'GGY_0',
  phone_number_country_callingcode = '+44'
WHERE phone_number_country_uniqueid = 'GGY_0'
  AND phone_number_country_callingcode = '+441481'
  AND phone_number IS NOT NULL AND phone_number <> ''
  AND LENGTH(phone_number) <= 26;
UPDATE users SET
  phone_number_country_uniqueid = 'GGY_0',
  phone_number_country_callingcode = '+44',
  phone_number_verified = 0,
  phone_number_verification_code_encrypted = NULL,
  phone_number_verification_code_issued_at = NULL
WHERE phone_number_country_uniqueid = 'GGY_0'
  AND phone_number_country_callingcode = '+441481'
  AND (phone_number IS NULL OR phone_number = '' OR LENGTH(phone_number) > 26);

UPDATE users SET
  phone_number = '1624' || phone_number,
  phone_number_country_uniqueid = 'IMN_0',
  phone_number_country_callingcode = '+44'
WHERE phone_number_country_uniqueid = 'IMN_0'
  AND phone_number_country_callingcode = '+441624'
  AND phone_number IS NOT NULL AND phone_number <> ''
  AND LENGTH(phone_number) <= 26;
UPDATE users SET
  phone_number_country_uniqueid = 'IMN_0',
  phone_number_country_callingcode = '+44',
  phone_number_verified = 0,
  phone_number_verification_code_encrypted = NULL,
  phone_number_verification_code_issued_at = NULL
WHERE phone_number_country_uniqueid = 'IMN_0'
  AND phone_number_country_callingcode = '+441624'
  AND (phone_number IS NULL OR phone_number = '' OR LENGTH(phone_number) > 26);

UPDATE users SET
  phone_number = '1534' || phone_number,
  phone_number_country_uniqueid = 'JEY_0',
  phone_number_country_callingcode = '+44'
WHERE phone_number_country_uniqueid = 'JEY_0'
  AND phone_number_country_callingcode = '+441534'
  AND phone_number IS NOT NULL AND phone_number <> ''
  AND LENGTH(phone_number) <= 26;
UPDATE users SET
  phone_number_country_uniqueid = 'JEY_0',
  phone_number_country_callingcode = '+44',
  phone_number_verified = 0,
  phone_number_verification_code_encrypted = NULL,
  phone_number_verification_code_issued_at = NULL
WHERE phone_number_country_uniqueid = 'JEY_0'
  AND phone_number_country_callingcode = '+441534'
  AND (phone_number IS NULL OR phone_number = '' OR LENGTH(phone_number) > 26);

UPDATE users SET
  phone_number = '787' || phone_number,
  phone_number_country_uniqueid = 'PRI_0',
  phone_number_country_callingcode = '+1'
WHERE phone_number_country_uniqueid = 'PRI_0'
  AND phone_number_country_callingcode = '+1787'
  AND phone_number IS NOT NULL AND phone_number <> ''
  AND LENGTH(phone_number) <= 27;
UPDATE users SET
  phone_number_country_uniqueid = 'PRI_0',
  phone_number_country_callingcode = '+1',
  phone_number_verified = 0,
  phone_number_verification_code_encrypted = NULL,
  phone_number_verification_code_issued_at = NULL
WHERE phone_number_country_uniqueid = 'PRI_0'
  AND phone_number_country_callingcode = '+1787'
  AND (phone_number IS NULL OR phone_number = '' OR LENGTH(phone_number) > 27);

UPDATE users SET
  phone_number = '939' || phone_number,
  phone_number_country_uniqueid = 'PRI_0',
  phone_number_country_callingcode = '+1'
WHERE phone_number_country_uniqueid = 'PRI_1'
  AND phone_number_country_callingcode = '+1939'
  AND phone_number IS NOT NULL AND phone_number <> ''
  AND LENGTH(phone_number) <= 27;
UPDATE users SET
  phone_number_country_uniqueid = 'PRI_0',
  phone_number_country_callingcode = '+1',
  phone_number_verified = 0,
  phone_number_verification_code_encrypted = NULL,
  phone_number_verification_code_issued_at = NULL
WHERE phone_number_country_uniqueid = 'PRI_1'
  AND phone_number_country_callingcode = '+1939'
  AND (phone_number IS NULL OR phone_number = '' OR LENGTH(phone_number) > 27);

UPDATE users SET
  phone_number = '79' || phone_number,
  phone_number_country_uniqueid = 'SJM_0',
  phone_number_country_callingcode = '+47'
WHERE phone_number_country_uniqueid = 'SJM_0'
  AND phone_number_country_callingcode = '+4779'
  AND phone_number IS NOT NULL AND phone_number <> ''
  AND LENGTH(phone_number) <= 28;
UPDATE users SET
  phone_number_country_uniqueid = 'SJM_0',
  phone_number_country_callingcode = '+47',
  phone_number_verified = 0,
  phone_number_verification_code_encrypted = NULL,
  phone_number_verification_code_issued_at = NULL
WHERE phone_number_country_uniqueid = 'SJM_0'
  AND phone_number_country_callingcode = '+4779'
  AND (phone_number IS NULL OR phone_number = '' OR LENGTH(phone_number) > 28);

UPDATE users SET
  phone_number = '698' || phone_number,
  phone_number_country_uniqueid = 'VAT_0',
  phone_number_country_callingcode = '+3906'
WHERE phone_number_country_uniqueid = 'VAT_0'
  AND phone_number_country_callingcode = '+3906698'
  AND phone_number IS NOT NULL AND phone_number <> ''
  AND LENGTH(phone_number) <= 27;
UPDATE users SET
  phone_number_country_uniqueid = 'VAT_0',
  phone_number_country_callingcode = '+3906',
  phone_number_verified = 0,
  phone_number_verification_code_encrypted = NULL,
  phone_number_verification_code_issued_at = NULL
WHERE phone_number_country_uniqueid = 'VAT_0'
  AND phone_number_country_callingcode = '+3906698'
  AND (phone_number IS NULL OR phone_number = '' OR LENGTH(phone_number) > 27);

UPDATE users SET
  phone_number = '269' || phone_number,
  phone_number_country_uniqueid = 'MYT_0',
  phone_number_country_callingcode = '+262'
WHERE phone_number_country_uniqueid = 'MYT_0'
  AND phone_number_country_callingcode = '+262269'
  AND phone_number IS NOT NULL AND phone_number <> ''
  AND LENGTH(phone_number) <= 27;
UPDATE users SET
  phone_number_country_uniqueid = 'MYT_0',
  phone_number_country_callingcode = '+262',
  phone_number_verified = 0,
  phone_number_verification_code_encrypted = NULL,
  phone_number_verification_code_issued_at = NULL
WHERE phone_number_country_uniqueid = 'MYT_0'
  AND phone_number_country_callingcode = '+262269'
  AND (phone_number IS NULL OR phone_number = '' OR LENGTH(phone_number) > 27);

UPDATE users SET
  phone_number = '639' || phone_number,
  phone_number_country_uniqueid = 'MYT_0',
  phone_number_country_callingcode = '+262'
WHERE phone_number_country_uniqueid = 'MYT_1'
  AND phone_number_country_callingcode = '+262639'
  AND phone_number IS NOT NULL AND phone_number <> ''
  AND LENGTH(phone_number) <= 27;
UPDATE users SET
  phone_number_country_uniqueid = 'MYT_0',
  phone_number_country_callingcode = '+262',
  phone_number_verified = 0,
  phone_number_verification_code_encrypted = NULL,
  phone_number_verification_code_issued_at = NULL
WHERE phone_number_country_uniqueid = 'MYT_1'
  AND phone_number_country_callingcode = '+262639'
  AND (phone_number IS NULL OR phone_number = '' OR LENGTH(phone_number) > 27);

-- Non-prefix changes: the effective number changes, so canonicalize the
-- identifier + code and require re-verification (number itself unchanged).
UPDATE users SET
  phone_number_country_uniqueid = 'ABW_0',
  phone_number_country_callingcode = '+297',
  phone_number_verified = 0,
  phone_number_verification_code_encrypted = NULL,
  phone_number_verification_code_issued_at = NULL
WHERE phone_number_country_uniqueid = 'ABW_1'
  AND phone_number_country_callingcode = '+5998';

UPDATE users SET
  phone_number_country_uniqueid = 'CCK_0',
  phone_number_country_callingcode = '+61',
  phone_number_verified = 0,
  phone_number_verification_code_encrypted = NULL,
  phone_number_verification_code_issued_at = NULL
WHERE phone_number_country_uniqueid = 'CCK_0'
  AND phone_number_country_callingcode = '+672';

UPDATE users SET
  phone_number_country_uniqueid = 'HMD_0',
  phone_number_country_callingcode = '+672',
  phone_number_verified = 0,
  phone_number_verification_code_encrypted = NULL,
  phone_number_verification_code_issued_at = NULL
WHERE phone_number_country_uniqueid = 'HMD_0'
  AND phone_number_country_callingcode = '+61';

UPDATE users SET
  phone_number_country_uniqueid = 'JAM_0',
  phone_number_country_callingcode = '+1876',
  phone_number_verified = 0,
  phone_number_verification_code_encrypted = NULL,
  phone_number_verification_code_issued_at = NULL
WHERE phone_number_country_uniqueid = 'JAM_1'
  AND phone_number_country_callingcode = '+1658';

UPDATE users SET
  phone_number_country_uniqueid = 'PCN_0',
  phone_number_country_callingcode = '+870',
  phone_number_verified = 0,
  phone_number_verification_code_encrypted = NULL,
  phone_number_verification_code_issued_at = NULL
WHERE phone_number_country_uniqueid = 'PCN_0'
  AND phone_number_country_callingcode = '+64';

UPDATE users SET
  phone_number_country_uniqueid = 'ATF_0',
  phone_number_country_callingcode = '+262',
  phone_number_verified = 0,
  phone_number_verification_code_encrypted = NULL,
  phone_number_verification_code_issued_at = NULL
WHERE phone_number_country_uniqueid = 'ATF_0'
  AND phone_number_country_callingcode = '+1';

-- Obsolete secondary identifiers (_1) already sitting at the canonical
-- code: the effective number is unchanged, so remap the id and PRESERVE
-- verification.
UPDATE users SET
  phone_number_country_uniqueid = 'BES_0'
WHERE phone_number_country_uniqueid = 'BES_1'
  AND phone_number_country_callingcode = '+599';

UPDATE users SET
  phone_number_country_uniqueid = 'CCK_0'
WHERE phone_number_country_uniqueid = 'CCK_1'
  AND phone_number_country_callingcode = '+61';

UPDATE users SET
  phone_number_country_uniqueid = 'PRI_0'
WHERE phone_number_country_uniqueid = 'PRI_1'
  AND phone_number_country_callingcode = '+1';

UPDATE users SET
  phone_number_country_uniqueid = 'MYT_0'
WHERE phone_number_country_uniqueid = 'MYT_1'
  AND phone_number_country_callingcode = '+262';

UPDATE users SET
  phone_number_country_uniqueid = 'ABW_0'
WHERE phone_number_country_uniqueid = 'ABW_1'
  AND phone_number_country_callingcode = '+297';

UPDATE users SET
  phone_number_country_uniqueid = 'JAM_0'
WHERE phone_number_country_uniqueid = 'JAM_1'
  AND phone_number_country_callingcode = '+1876';

-- Dirty rows: an affected country identifier carrying a code that is NULL
-- or neither ITS OWN old code nor the canonical code. Each identifier has
-- its own valid-code set (its old code + the canonical code), so a
-- mismatched sibling pair (e.g. BES_0 carrying BES_1's old code +5994) is
-- still caught -- a per-country union whitelist would wrongly permit it.
-- Force to the canonical (id, code) and re-verify. The NULL branch is
-- explicit because `code <> x` is unknown (not true) for NULL in SQL
-- three-valued logic.
UPDATE users SET
  phone_number_country_uniqueid = 'ALA_0',
  phone_number_country_callingcode = '+358',
  phone_number_verified = 0,
  phone_number_verification_code_encrypted = NULL,
  phone_number_verification_code_issued_at = NULL
WHERE (phone_number_country_uniqueid = 'ALA_0'
       AND (phone_number_country_callingcode IS NULL
            OR phone_number_country_callingcode NOT IN ('+358', '+35818')));

UPDATE users SET
  phone_number_country_uniqueid = 'BES_0',
  phone_number_country_callingcode = '+599',
  phone_number_verified = 0,
  phone_number_verification_code_encrypted = NULL,
  phone_number_verification_code_issued_at = NULL
WHERE (phone_number_country_uniqueid = 'BES_0'
       AND (phone_number_country_callingcode IS NULL
            OR phone_number_country_callingcode NOT IN ('+599', '+5993')))
   OR (phone_number_country_uniqueid = 'BES_1'
       AND (phone_number_country_callingcode IS NULL
            OR phone_number_country_callingcode NOT IN ('+599', '+5994')));

UPDATE users SET
  phone_number_country_uniqueid = 'CCK_0',
  phone_number_country_callingcode = '+61',
  phone_number_verified = 0,
  phone_number_verification_code_encrypted = NULL,
  phone_number_verification_code_issued_at = NULL
WHERE (phone_number_country_uniqueid = 'CCK_0'
       AND (phone_number_country_callingcode IS NULL
            OR phone_number_country_callingcode NOT IN ('+61', '+672')))
   OR (phone_number_country_uniqueid = 'CCK_1'
       AND (phone_number_country_callingcode IS NULL
            OR phone_number_country_callingcode NOT IN ('+61', '+6189162')));

UPDATE users SET
  phone_number_country_uniqueid = 'CUW_0',
  phone_number_country_callingcode = '+599',
  phone_number_verified = 0,
  phone_number_verification_code_encrypted = NULL,
  phone_number_verification_code_issued_at = NULL
WHERE (phone_number_country_uniqueid = 'CUW_0'
       AND (phone_number_country_callingcode IS NULL
            OR phone_number_country_callingcode NOT IN ('+599', '+5999')));

UPDATE users SET
  phone_number_country_uniqueid = 'CXR_0',
  phone_number_country_callingcode = '+61',
  phone_number_verified = 0,
  phone_number_verification_code_encrypted = NULL,
  phone_number_verification_code_issued_at = NULL
WHERE (phone_number_country_uniqueid = 'CXR_0'
       AND (phone_number_country_callingcode IS NULL
            OR phone_number_country_callingcode NOT IN ('+61', '+6189164')));

UPDATE users SET
  phone_number_country_uniqueid = 'GGY_0',
  phone_number_country_callingcode = '+44',
  phone_number_verified = 0,
  phone_number_verification_code_encrypted = NULL,
  phone_number_verification_code_issued_at = NULL
WHERE (phone_number_country_uniqueid = 'GGY_0'
       AND (phone_number_country_callingcode IS NULL
            OR phone_number_country_callingcode NOT IN ('+44', '+441481')));

UPDATE users SET
  phone_number_country_uniqueid = 'IMN_0',
  phone_number_country_callingcode = '+44',
  phone_number_verified = 0,
  phone_number_verification_code_encrypted = NULL,
  phone_number_verification_code_issued_at = NULL
WHERE (phone_number_country_uniqueid = 'IMN_0'
       AND (phone_number_country_callingcode IS NULL
            OR phone_number_country_callingcode NOT IN ('+44', '+441624')));

UPDATE users SET
  phone_number_country_uniqueid = 'JEY_0',
  phone_number_country_callingcode = '+44',
  phone_number_verified = 0,
  phone_number_verification_code_encrypted = NULL,
  phone_number_verification_code_issued_at = NULL
WHERE (phone_number_country_uniqueid = 'JEY_0'
       AND (phone_number_country_callingcode IS NULL
            OR phone_number_country_callingcode NOT IN ('+44', '+441534')));

UPDATE users SET
  phone_number_country_uniqueid = 'PRI_0',
  phone_number_country_callingcode = '+1',
  phone_number_verified = 0,
  phone_number_verification_code_encrypted = NULL,
  phone_number_verification_code_issued_at = NULL
WHERE (phone_number_country_uniqueid = 'PRI_0'
       AND (phone_number_country_callingcode IS NULL
            OR phone_number_country_callingcode NOT IN ('+1', '+1787')))
   OR (phone_number_country_uniqueid = 'PRI_1'
       AND (phone_number_country_callingcode IS NULL
            OR phone_number_country_callingcode NOT IN ('+1', '+1939')));

UPDATE users SET
  phone_number_country_uniqueid = 'SJM_0',
  phone_number_country_callingcode = '+47',
  phone_number_verified = 0,
  phone_number_verification_code_encrypted = NULL,
  phone_number_verification_code_issued_at = NULL
WHERE (phone_number_country_uniqueid = 'SJM_0'
       AND (phone_number_country_callingcode IS NULL
            OR phone_number_country_callingcode NOT IN ('+47', '+4779')));

UPDATE users SET
  phone_number_country_uniqueid = 'VAT_0',
  phone_number_country_callingcode = '+3906',
  phone_number_verified = 0,
  phone_number_verification_code_encrypted = NULL,
  phone_number_verification_code_issued_at = NULL
WHERE (phone_number_country_uniqueid = 'VAT_0'
       AND (phone_number_country_callingcode IS NULL
            OR phone_number_country_callingcode NOT IN ('+3906', '+3906698')));

UPDATE users SET
  phone_number_country_uniqueid = 'MYT_0',
  phone_number_country_callingcode = '+262',
  phone_number_verified = 0,
  phone_number_verification_code_encrypted = NULL,
  phone_number_verification_code_issued_at = NULL
WHERE (phone_number_country_uniqueid = 'MYT_0'
       AND (phone_number_country_callingcode IS NULL
            OR phone_number_country_callingcode NOT IN ('+262', '+262269')))
   OR (phone_number_country_uniqueid = 'MYT_1'
       AND (phone_number_country_callingcode IS NULL
            OR phone_number_country_callingcode NOT IN ('+262', '+262639')));

UPDATE users SET
  phone_number_country_uniqueid = 'ABW_0',
  phone_number_country_callingcode = '+297',
  phone_number_verified = 0,
  phone_number_verification_code_encrypted = NULL,
  phone_number_verification_code_issued_at = NULL
WHERE (phone_number_country_uniqueid = 'ABW_0'
       AND (phone_number_country_callingcode IS NULL
            OR phone_number_country_callingcode NOT IN ('+297')))
   OR (phone_number_country_uniqueid = 'ABW_1'
       AND (phone_number_country_callingcode IS NULL
            OR phone_number_country_callingcode NOT IN ('+297', '+5998')));

UPDATE users SET
  phone_number_country_uniqueid = 'HMD_0',
  phone_number_country_callingcode = '+672',
  phone_number_verified = 0,
  phone_number_verification_code_encrypted = NULL,
  phone_number_verification_code_issued_at = NULL
WHERE (phone_number_country_uniqueid = 'HMD_0'
       AND (phone_number_country_callingcode IS NULL
            OR phone_number_country_callingcode NOT IN ('+61', '+672')));

UPDATE users SET
  phone_number_country_uniqueid = 'JAM_0',
  phone_number_country_callingcode = '+1876',
  phone_number_verified = 0,
  phone_number_verification_code_encrypted = NULL,
  phone_number_verification_code_issued_at = NULL
WHERE (phone_number_country_uniqueid = 'JAM_0'
       AND (phone_number_country_callingcode IS NULL
            OR phone_number_country_callingcode NOT IN ('+1876')))
   OR (phone_number_country_uniqueid = 'JAM_1'
       AND (phone_number_country_callingcode IS NULL
            OR phone_number_country_callingcode NOT IN ('+1658', '+1876')));

UPDATE users SET
  phone_number_country_uniqueid = 'PCN_0',
  phone_number_country_callingcode = '+870',
  phone_number_verified = 0,
  phone_number_verification_code_encrypted = NULL,
  phone_number_verification_code_issued_at = NULL
WHERE (phone_number_country_uniqueid = 'PCN_0'
       AND (phone_number_country_callingcode IS NULL
            OR phone_number_country_callingcode NOT IN ('+64', '+870')));

UPDATE users SET
  phone_number_country_uniqueid = 'ATF_0',
  phone_number_country_callingcode = '+262',
  phone_number_verified = 0,
  phone_number_verification_code_encrypted = NULL,
  phone_number_verification_code_issued_at = NULL
WHERE (phone_number_country_uniqueid = 'ATF_0'
       AND (phone_number_country_callingcode IS NULL
            OR phone_number_country_callingcode NOT IN ('+1', '+262')));

-- Repair pre-existing NULLs in the plain-string phone columns (models.User
-- scans them as Go string, which cannot hold SQL NULL -> GetUserById errors).
UPDATE users SET phone_number = '' WHERE phone_number IS NULL;
UPDATE users SET phone_number_country_uniqueid = '' WHERE phone_number_country_uniqueid IS NULL;
UPDATE users SET phone_number_country_callingcode = '' WHERE phone_number_country_callingcode IS NULL;

-- Address country: drop removed countries and repair NULLs left by 000019
-- (address_country is also a plain Go string and NULL-intolerant on read).
UPDATE users SET address_country = ''
WHERE address_country IN ('AN', 'YU') OR address_country IS NULL;
