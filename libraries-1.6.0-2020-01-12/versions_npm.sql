CREATE TABLE versions_npm (
    id INT PRIMARY KEY,
    platform VARCHAR(255),
    project_name VARCHAR(255),
    project_id INT,
    number VARCHAR(255),
    published_timestamp DATETIME,
    created_timestamp DATETIME,
    updated_timestamp DATETIME
);