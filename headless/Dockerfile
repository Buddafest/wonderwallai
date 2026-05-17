FROM mcr.microsoft.com/playwright/python:v1.48.0-jammy

WORKDIR /app

COPY headless/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY headless/ ./

EXPOSE 8080

CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT:-8080}"]
