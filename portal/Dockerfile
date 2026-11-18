FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py game.json ./
COPY sploits ./sploits
COPY learn.html theory.html ./
EXPOSE 9000
CMD ["gunicorn", "-w", "1", "--threads", "8", "-b", "0.0.0.0:9000", "app:app"]
