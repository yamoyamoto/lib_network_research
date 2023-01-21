CREATE TABLE dependencies_cargo (
    id INT PRIMARY KEY,
    platform VARCHAR(255),
    project_name VARCHAR(255),
    project_id INT,
    version_number VARCHAR(255),
    version_id INT,
    dependency_name VARCHAR(255),
    dependency_platform VARCHAR(255),
    dependency_kind VARCHAR(255),
    optional_dependency VARCHAR(255),
    dependency_requirements VARCHAR(255),
    dependency_project_id INT
);

CREATE TABLE dependencies_npm (
    id INT PRIMARY KEY,
    platform VARCHAR(255),
    project_name VARCHAR(255),
    project_id INT,
    version_number VARCHAR(255),
    version_id INT,
    dependency_name VARCHAR(255),
    dependency_platform VARCHAR(255),
    dependency_kind VARCHAR(255),
    optional_dependency VARCHAR(255),
    dependency_requirements VARCHAR(255),
    dependency_project_id INT
);