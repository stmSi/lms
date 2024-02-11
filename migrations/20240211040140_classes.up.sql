-- Add up migration script here
-- Classes Table
CREATE TABLE classes (
    class_id SERIAL PRIMARY KEY,
    title VARCHAR(255),
    user_id INT REFERENCES users(id)
);

-- Student Classes Enrollment Table
CREATE TABLE student_classes_enrollment (
    enrollment_id SERIAL PRIMARY KEY,
    class_id INT REFERENCES classes(class_id),
    user_id INT REFERENCES users(id)
);

