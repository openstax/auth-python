FROM python:3.7-slim

ENV PYTHONUNBUFFERED 1

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /code
COPY . /code/

RUN python setup.py develop

# Install the unit test libraries
RUN pip install pytest pytest-mock ipdb --user

ENTRYPOINT ["/code/docker/entrypoint"]
