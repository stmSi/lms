-- Student Portfolio Table
CREATE TABLE student_portfolio (
    portfolio_id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(id),
    content_html_or_markdown TEXT
);

-- Teacher Portfolio Table
CREATE TABLE teacher_portfolio (
    portfolio_id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(id),
    content_html_or_markdown TEXT
);
