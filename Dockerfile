# Use an official Python runtime as a parent image
FROM python:3.7-slim

# Set the working directory to /app
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Install any needed packages specified in requirements.txt
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc and-build-dependencies \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --trusted-host pypi.python.org -r requirements.txt \
    && apk del build-dependencies

# Make port 80 available to the world outside this container
EXPOSE 80

# Run app.py when the container launches
CMD ["python", "lsdb-www.py"]
