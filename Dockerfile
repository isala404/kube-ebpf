FROM alpine:3

RUN apk add bcc-tools py3-pip py3-bcc

RUN pip install prometheus_client requests

WORKDIR /app

COPY . .

ENV KUBERNETES_SERVICE_HOST=
ENV KUBERNETES_PORT_443_TCP_PORT=
ENV NODE_NAME=
ENV DEBUG=

CMD ["python3", "main.py"]