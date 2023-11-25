# Use the official Python image as a parent image
FROM python:3.11.5

# Set the working directory to /app
WORKDIR /app

# Copy the contents of the "myapp" directory into the container at /app
COPY app/ /app

# Install any needed packages specified in requirements.txt
RUN pip install -r /app/requirements.txt

# Make port 8000 available to the world outside this container
EXPOSE 8000

# Define environment variable
ENV NAME World

# Run app.py when the container launches
CMD ["python", "/app/app.py"]