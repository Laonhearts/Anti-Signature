# 베이스 이미지를 Python 3.9로 설정
FROM python:3.9-slim

# 작업 디렉토리 생성
WORKDIR /usr/src/app

# 의존성 파일을 복사하고 필요 라이브러리 설치
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# 소스 파일 복사
COPY . .

# 스크립트를 실행할 수 있도록 엔트리포인트 설정
ENTRYPOINT ["python", "main.py"]
