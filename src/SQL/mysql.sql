CREATE TABLE file_integrity_logs (

    id INT AUTO_INCREMENT PRIMARY KEY,
    file_name VARCHAR(255),
    action VARCHAR(255), -- 무결성 검사, 랜섬웨어 감염 여부, 안티디버깅 적용 여부 등
    status VARCHAR(255), -- 성공, 실패, 감염됨 등 상태
    timestamp DATETIME

);

CREATE TABLE file_signature_logs (

    id INT AUTO_INCREMENT PRIMARY KEY,
    file_name VARCHAR(255),
    signature_before VARCHAR(255),
    signature_after VARCHAR(255),
    timestamp DATETIME

);
