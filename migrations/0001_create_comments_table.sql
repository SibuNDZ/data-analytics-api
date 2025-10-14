-- Migration number: 0001     2024-12-27T22:04:18.794Z

-- Create comments table if it doesn't exist
CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    author TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Insert some sample data into our comments table.
INSERT INTO comments (author, content)
VALUES
    ('Mili', 'Congrats!'),
    ('Noluthando', 'Great job!'),
    ('Bonke', 'Keep up the good work!');