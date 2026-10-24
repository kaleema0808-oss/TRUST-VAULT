-- Add file metadata columns to documents table.
-- object_key was already added in 001; we add original_name and mime_type here.
ALTER TABLE documents
  ADD COLUMN original_name VARCHAR(255) NULL AFTER category,
  ADD COLUMN mime_type VARCHAR(127) NULL AFTER original_name,
  ADD COLUMN file_size BIGINT UNSIGNED NULL AFTER mime_type;
