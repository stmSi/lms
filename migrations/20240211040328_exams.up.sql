-- Exams Table
CREATE TABLE exams (
    exam_id SERIAL PRIMARY KEY,
    title VARCHAR(255),
    class_id INT REFERENCES classes(class_id),
    timer INTERVAL,
    marking_schema TEXT
);

-- Student Exams Table
CREATE TABLE student_exams (
    student_exam_id SERIAL PRIMARY KEY,
    exam_id INT REFERENCES exams(exam_id),
    user_id INT REFERENCES users(id),
    score NUMERIC
);

