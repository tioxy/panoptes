FROM python:alpine

# Copy all Panoptes source code to /app/
WORKDIR /app/
COPY . /app/

# Install Panoptes Module locally
RUN python setup.py install
