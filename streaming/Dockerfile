FROM python:3.12-slim
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
USER 65532:65532
CMD ["uvicorn","app:app","--host","0.0.0.0","--port","8000","--workers","1","--ws-max-size","16384","--ws-max-queue","4","--limit-concurrency","64","--timeout-keep-alive","5"]
