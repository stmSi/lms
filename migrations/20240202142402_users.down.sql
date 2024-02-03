-- Start of down.sql

-- Drop the users table first to avoid foreign key constraint errors
DROP TABLE IF EXISTS users CASCADE;

-- Drop the roles table next
DROP TABLE IF EXISTS roles CASCADE;

-- End of down.sql
