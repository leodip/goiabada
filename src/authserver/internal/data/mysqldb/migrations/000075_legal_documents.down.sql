-- Reverses migration 000075 (#622). Every legal document and every published version is lost.
DROP TABLE `legal_document_versions`;
DROP TABLE `legal_documents`;
