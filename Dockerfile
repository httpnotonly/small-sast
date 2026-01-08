FROM python:3-alpine3.12
WORKDIR /code
RUN apk add --no-cache git jq curl
COPY main.py /usr/bin/small-sast
RUN chmod +x /usr/bin/small-sast

ENTRYPOINT []
