-- Migration number: 0001 	 2024-12-27T22:04:18.794Z
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'comments')
BEGIN
    CREATE TABLE comments (
        id INTEGER PRIMARY KEY NOT NULL,
        author TEXT NOT NULL,
        content TEXT NOT NULL
    );
END

-- Insert some sample data into our comments table.
INSERT INTO comments (author, content)
VALUES
    ('Mili', 'Congrats!'),
    ('Noluthando', 'Great job!'),
    ('Bonke', 'Keep up the good work!')
;
