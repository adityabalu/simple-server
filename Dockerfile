FROM python:3.9-slim

# Install system packages
RUN apt-get update && apt-get install -y \
    nginx \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
COPY templates/ ./templates/

RUN mkdir uploads

# Configure Nginx
COPY nginx.conf /etc/nginx/nginx.conf

EXPOSE 80

CMD ["python", "app.py"]