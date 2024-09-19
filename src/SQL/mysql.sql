USE signature;

CREATE TABLE IF NOT EXISTS operation_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    operation VARCHAR(255),
    details VARCHAR(255),
    status VARCHAR(255),
    timestamp DATETIME
);
