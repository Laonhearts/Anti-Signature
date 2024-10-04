# Python 3.9 이미지 사용
FROM python:3.9-slim

# 작업 디렉토리 설정
WORKDIR /app

# 필요한 파일 복사
COPY requirements.txt ./
COPY setup.sh ./
COPY . .

# 기본 패키지 설치
RUN apt-get update && apt-get install -y \
    libaio1 gcc make \
    && rm -rf /var/lib/apt/lists/*

# Python 라이브러리 설치
RUN pip install --no-cache-dir -r requirements.txt

# Oracle Instant Client 설치 (cx_Oracle 용)
RUN curl -O https://download.oracle.com/otn_software/linux/instantclient/instantclient-basiclite-linux.x64-19.11.0.0.0dbru.zip && \
    unzip instantclient-basiclite-linux.x64-19.11.0.0.0dbru.zip -d /opt/oracle && \
    rm instantclient-basiclite-linux.x64-19.11.0.0.0dbru.zip && \
    export LD_LIBRARY_PATH=/opt/oracle/instantclient_19_11:$LD_LIBRARY_PATH

# 실행 권한 부여 및 셋업
RUN chmod +x setup.sh
RUN ./setup.sh

# 프로그램 실행
CMD ["python", "main.py"]
