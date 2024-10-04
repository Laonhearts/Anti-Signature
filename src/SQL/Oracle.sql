-- 데이터베이스 선택은 Oracle에서 필요하지 않음

-- 테이블 삭제
BEGIN
    EXECUTE IMMEDIATE 'DROP TABLE file_integrity_logs CASCADE CONSTRAINTS';
EXCEPTION
    WHEN OTHERS THEN
        IF SQLCODE != -942 THEN
            RAISE;
        END IF;
END;
/

BEGIN
    EXECUTE IMMEDIATE 'DROP TABLE file_signature_logs CASCADE CONSTRAINTS';
EXCEPTION
    WHEN OTHERS THEN
        IF SQLCODE != -942 THEN
            RAISE;
        END IF;
END;
/

BEGIN
    EXECUTE IMMEDIATE 'DROP TABLE operation_logs CASCADE CONSTRAINTS';
EXCEPTION
    WHEN OTHERS THEN
        IF SQLCODE != -942 THEN
            RAISE;
        END IF;
END;
/

-- file_integrity_logs 테이블 생성
CREATE TABLE file_integrity_logs (
    id NUMBER PRIMARY KEY,
    file_name VARCHAR2(255),
    action VARCHAR2(255),
    status VARCHAR2(255),
    timestamp TIMESTAMP
);

-- file_integrity_logs SEQUENCE 생성
CREATE SEQUENCE file_integrity_logs_seq START WITH 1 INCREMENT BY 1;

-- file_integrity_logs 테이블에 트리거 생성하여 id 자동 증가
CREATE OR REPLACE TRIGGER file_integrity_logs_trigger
BEFORE INSERT ON file_integrity_logs
FOR EACH ROW
BEGIN
    SELECT file_integrity_logs_seq.NEXTVAL INTO :NEW.id FROM dual;
END;
/

-- file_signature_logs 테이블 생성
CREATE TABLE file_signature_logs (
    id NUMBER PRIMARY KEY,
    file_name VARCHAR2(255),
    signature_before VARCHAR2(255),
    signature_after VARCHAR2(255),
    timestamp TIMESTAMP
);

-- file_signature_logs SEQUENCE 생성
CREATE SEQUENCE file_signature_logs_seq START WITH 1 INCREMENT BY 1;

-- file_signature_logs 테이블에 트리거 생성하여 id 자동 증가
CREATE OR REPLACE TRIGGER file_signature_logs_trigger
BEFORE INSERT ON file_signature_logs
FOR EACH ROW
BEGIN
    SELECT file_signature_logs_seq.NEXTVAL INTO :NEW.id FROM dual;
END;
/

-- operation_logs 테이블 생성
CREATE TABLE operation_logs (
    id NUMBER PRIMARY KEY,
    operation VARCHAR2(255),
    details VARCHAR2(255),
    status VARCHAR2(255),
    timestamp TIMESTAMP
);

-- operation_logs SEQUENCE 생성
CREATE SEQUENCE operation_logs_seq START WITH 1 INCREMENT BY 1;

-- operation_logs 테이블에 트리거 생성하여 id 자동 증가
CREATE OR REPLACE TRIGGER operation_logs_trigger
BEFORE INSERT ON operation_logs
FOR EACH ROW
BEGIN
    SELECT operation_logs_seq.NEXTVAL INTO :NEW.id FROM dual;
END;
/
