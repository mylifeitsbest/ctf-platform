FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY checker_lib.py run_checkers.py game.json ./
COPY checkers ./checkers
CMD ["python", "-u", "run_checkers.py"]
