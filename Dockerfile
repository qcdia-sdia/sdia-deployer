FROM python:3.8-buster

RUN apt update -y && apt upgrade -y

RUN mkdir -p /usr/src/app
WORKDIR /usr/src/app

COPY requirements.txt /usr/src/app/


RUN pip3 install --no-cache-dir -r requirements.txt

COPY . /usr/src/app

CMD python3 __main__.py $RABBITMQ_HOST deployer
