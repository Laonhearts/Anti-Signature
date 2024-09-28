USE signature;

DROP TABLE IF EXISTS file_integrity_logs;

CREATE TABLE file_integrity_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    file_name VARCHAR(255),
    action VARCHAR(255),
    status VARCHAR(255),
    timestamp DATETIME
);

DROP TABLE IF EXISTS file_signature_logs;

CREATE TABLE file_signature_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    file_name VARCHAR(255),
    signature_before VARCHAR(255),
    signature_after VARCHAR(255),
    timestamp DATETIME
);

CREATE TABLE IF NOT EXISTS operation_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    operation VARCHAR(255),
    details VARCHAR(255),
    status VARCHAR(255),
    timestamp DATETIME
);
