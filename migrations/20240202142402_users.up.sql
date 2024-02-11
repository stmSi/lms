-- Add migration script here
CREATE TABLE roles (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) UNIQUE NOT NULL
);

CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role_id INTEGER NOT NULL,
    FOREIGN KEY (role_id) REFERENCES roles(id)
);

-- Teacher Details (additional information for teachers)
CREATE TABLE teacher_details (
    user_id BIGINT NOT NULL,
    additional_info TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Student Details (additional information for students)
CREATE TABLE student_details (
    user_id BIGINT NOT NULL,
    enrollment_info TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
