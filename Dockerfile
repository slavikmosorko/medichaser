FROM python:3.13-slim AS base

RUN apt-get -y update && apt-get -y install wget tini git nano vim procps screen
RUN wget https://github.com/tsl0922/ttyd/releases/download/1.7.7/ttyd.x86_64 -O /usr/bin/ttyd
RUN chmod +x /usr/bin/ttyd

EXPOSE 7681

WORKDIR /app

FROM base AS poetry
RUN --mount=type=cache,target=/root/.cache/pip pip install poetry==2.0.1
RUN --mount=type=cache,target=/root/.cache/pip poetry self add poetry-plugin-export
COPY poetry.lock pyproject.toml ./
RUN poetry export -o  /requirements.txt --without-hashes --without="dev"

FROM base AS app

COPY --from=poetry /requirements.txt .
RUN pip install -r requirements.txt

COPY mediczuwacz.py medihunter_notifiers.py ./

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["ttyd", "-W", "bash"]
