FROM python:alpine

# Copy all Panoptes source code to /app/
WORKDIR /app/
COPY . /app/

# Install Panoptes Module locally
RUN apk add --no-cache git python-dev libffi-dev openssl-dev build-base \
 && pip install --upgrade poetry \
 && poetry install \
 && apk del python-dev libffi-dev openssl-dev build-base

ENTRYPOINT ["poetry", "run"]
