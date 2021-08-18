FROM python:3.8

RUN mkdir -p /src/

RUN apt-get update
RUN apt-get -y install libgdal-dev

COPY Pipfile* /src/
RUN cd /src/ && \
    pip install pipenv && \
    pip install Werkzeug && \
    pipenv install --system --deploy --ignore-pipfile 

COPY . /src/
WORKDIR /src/

ADD https://github.com/ufoscout/docker-compose-wait/releases/download/2.7.3/wait /wait
RUN chmod +x /wait

CMD ["uvicorn", "app.main:auth_service", "--host", "0.0.0.0", "--port", "8000"]