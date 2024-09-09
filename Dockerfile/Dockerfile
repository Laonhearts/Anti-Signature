# 베이스 이미지 선택 (Python 최신 버전 사용)
FROM python:3.9-slim

# 작업 디렉토리 설정
WORKDIR /app

# 요구 사항 파일을 이미지에 복사
COPY requirements.txt .

# 패키지 설치
RUN pip install --no-cache-dir -r requirements.txt

# 소스 코드를 이미지에 복사
COPY . .

# 스크립트를 실행할 기본 명령어 설정
CMD ["python", "main.py"]
