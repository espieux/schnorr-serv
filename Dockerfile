# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Setup the working directory in the container
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Install the required dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Make port 5000 available, then run the Flask app
EXPOSE 5000

CMD ["python", "schnorr_server.py"]
