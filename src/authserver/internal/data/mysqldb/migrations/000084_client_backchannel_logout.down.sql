-- Migration 000084 down: drop a client's back-channel logout settings, and every one set since with
-- them.
ALTER TABLE `clients` DROP COLUMN `backchannel_logout_session_required`;
ALTER TABLE `clients` DROP COLUMN `backchannel_logout_uri`;
