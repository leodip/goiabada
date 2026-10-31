-- Reverses migration 000071 (#147). Every client's sign-out redirect URIs are lost.
DROP TABLE [post_logout_redirect_uris];
