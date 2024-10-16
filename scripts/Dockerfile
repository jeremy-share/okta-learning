FROM python:3.11

RUN mkdir -p /opt/project
WORKDIR /opt/project

COPY requirements.in ./
RUN pip3 install -r requirements.in
