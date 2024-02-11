-- Assignments Table
CREATE TABLE assignments (
    assignment_id SERIAL PRIMARY KEY,
    title VARCHAR(255),
    description TEXT,
    class_id INT REFERENCES classes(class_id)
);

-- Assignment Questions Table
CREATE TABLE assignment_questions (
    question_id SERIAL PRIMARY KEY,
    assignment_id INT REFERENCES assignments(assignment_id),
    question_text TEXT
);

-- Assignment Answers Table
CREATE TABLE assignment_answers (
    answer_id SERIAL PRIMARY KEY,
    question_id INT REFERENCES assignment_questions(question_id),
    user_id INT REFERENCES users(id),
    answer_text TEXT
);

