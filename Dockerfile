FROM ubuntu/postgres
#FROM python:3
LABEL maintainer="Luis F Monge @lukky86"
LABEL description="Grafiki Project Dockerfile."

ENV PYTHONUNBUFFERED=1

WORKDIR /code

# Install dependences
RUN apt-get -y update
RUN apt-get install sudo
RUN sudo apt-get install net-tools
RUN sudo apt install python3 python3-pip libpq-dev -y
COPY requirements.txt /code/
RUN pip3 install -r /code/requirements.txt

USER root

# Copy project
COPY ./ /opt/

# Copy initial sql file
COPY init_db.sh /docker-entrypoint-initdb.d/

COPY init_django.sh /
RUN chmod +x /init_django.sh

WORKDIR /opt/grafiki