FROM python:3.9-slim

WORKDIR /app

COPY app.py .
COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY init_db.py .

EXPOSE 5000

CMD ["sh", "-c", "python init_db.py && python app.py"]

