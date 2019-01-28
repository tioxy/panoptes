FROM python:alpine

# Copy all Panoptes source code to /app/
WORKDIR /app/
COPY . /app/

# Install Panoptes Module locally
RUN apk add --no-cache git \
 && pip install --upgrade poetry \
 && poetry install

ENTRYPOINT ["poetry", "run"]
