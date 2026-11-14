-- Reverses migration 000095 (#818). Every email template edit is lost, and every email is sent
-- with the built-in text again.
DROP TABLE [email_templates];
