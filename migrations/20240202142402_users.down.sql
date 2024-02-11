-- Start of down.sql

DROP TABLE IF EXISTS student_portfolio CASCADE;

DROP TABLE IF EXISTS teacher_portfolio CASCADE;

-- Drop the users table first to avoid foreign key constraint errors
DROP TABLE IF EXISTS users CASCADE;

-- Drop the roles table next
DROP TABLE IF EXISTS roles CASCADE;

-- End of down.sql
