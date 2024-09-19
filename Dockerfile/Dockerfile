# 베이스 이미지로 Python 3.9 사용
FROM python:3.9-slim

# 작업 디렉토리 생성
WORKDIR /app

# 필요한 파일들을 복사
COPY requirements.txt ./

# 필요한 패키지 설치
RUN pip install --no-cache-dir -r requirements.txt

# 소스 파일 복사
COPY . .

# 포트 노출 (선택적, 네트워크 모니터링용 포트가 있으면 설정)
EXPOSE 8080

# 실행 명령어 설정
CMD ["python", "main.py"]
