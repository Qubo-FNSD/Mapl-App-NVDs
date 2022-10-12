# syntax=docker/dockerfile:1

FROM tiangolo/uvicorn-gunicorn:python3.8-slim

WORKDIR /

COPY requirements.txt /requirements.txt

RUN pip install pipreqs

RUN pipreqs

COPY application /app

RUN mkdir "logs"

RUN cd logs

RUN touch serverLog.log

RUN cd ..

ENV DOCKER_CONTAINER Yes

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--log-config", "./app/log.ini"]
