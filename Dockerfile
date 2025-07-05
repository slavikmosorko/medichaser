FROM python:3.13-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get -y update && apt-get -y install wget tini git nano vim procps screen
RUN wget https://github.com/tsl0922/ttyd/releases/download/1.7.7/ttyd.x86_64 -O /usr/bin/ttyd
RUN chmod +x /usr/bin/ttyd

RUN groupadd --gid 1000 selenium && useradd -m --uid 1000 --gid 1000 -s /bin/bash selenium

# Install Chrome and its dependencies
# Using a specific version of Chrome is often safer for consistency, but 'google-chrome-stable' is fine for general use.
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install -y \
    wget \
    gnupg \
    unzip \
    libnss3 \
    libxss1 \
    libappindicator1 \
    fonts-liberation \
    libgbm-dev \
    libasound2 \
    libatk-bridge2.0-0 \
    libgtk-3-0 \
    # For headless Chrome specifically, if you encounter issues
    # xvfb # if using xvfb to run graphical applications
    # xauth # if using xvfb
    # Add Google Chrome repository
    && wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | apt-key add - \
    && echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google-chrome.list \
    && apt-get update && apt-get install -y google-chrome-stable \
    # Clean up apt caches to reduce image size
    && rm -rf /var/lib/apt/lists/*

FROM base AS poetry
RUN --mount=type=cache,target=/root/.cache/pip pip install poetry==2.0.1
RUN --mount=type=cache,target=/root/.cache/pip poetry self add poetry-plugin-export
COPY poetry.lock pyproject.toml ./
RUN poetry export -o  /requirements.txt --without-hashes --without="dev"

FROM base AS app

COPY --from=poetry /requirements.txt /requirements.txt
RUN --mount=type=cache,target=/root/.cache/pip pip install -r /requirements.txt

USER selenium

ENV PROMPT_COMMAND='history -a'
ENV HISTFILE=/app/data/.bash_history

WORKDIR /app

COPY mediczuwacz.py medihunter_notifiers.py LICENSE ./

EXPOSE 7681
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["ttyd", "-W", "bash"]
