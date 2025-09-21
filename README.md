# MediChaser

[![Docker Pulls](https://img.shields.io/docker/pulls/rafsaf/medichaser.svg)](https://hub.docker.com/r/rafsaf/medichaser)
[![Latest release](https://img.shields.io/github/v/release/rafsaf/medichaser)](https://github.com/rafsaf/medichaser/releases/latest)

MediChaser is a tool for automating Medicover appointment searches. It interacts with the Medicover website, handles login and MFA, and sends notifications when appointments are found.

The application is designed to be run in a Docker container and includes a `ttyd` web terminal for remote management.

![medichaser-example.png](./medichaser-example.png)

---

## Features

- Search for appointments by region, specialty, clinic, doctor, date range, and language at a configurable interval.
- Run multiple appointment searches in parallel from a TOML config with deduplicated notifications.
- Handles Multi-Factor Authentication (MFA).
- Sends notifications via Gotify, Telegram, Pushbullet, Pushover, Prowl and XMPP.
- Remote management through an integrated `ttyd` web terminal.
- Persistent data storage for sessions, tokens, and logs.
- Bullet proof design - created for long runs.
- Shell autocomplete for `medichaser.py`.

---

## How It Works

MediChaser automates Medicover interactions using two login methods, both supporting Multi-Factor Authentication (MFA):

-   **Direct HTTP Requests (Default)**: Fast and efficient, interacting directly with the Medicover API.
-   **Selenium-based Login**: An alternative using a headless browser, which can be enabled with the `SELENIUM_LOGIN` environment variable.

The included `ttyd` service provides command-line access to the container via a web browser.

---

## Setup

**Prerequisites**: Docker and Docker Compose.

1. **Clone the repository:**

    ```bash
    git clone https://github.com/rafsaf/medichaser.git
    cd medichaser
    ```

2. **Create `.env` file:**

    ```bash
    cp .env.example .env
    ```

3. **Configure credentials:**

    Edit the `.env` file with your Medicover username and password.

    ```bash
    MEDICOVER_USER="your_username"
    MEDICOVER_PASS="your_password"
    ```

    Configure notifiers in this file as well (see below).

4. **Run with Docker Compose:**

    ```bash
    docker compose up -d
    ```

5. **Access the web terminal:**

    Navigate to `http://localhost:7681`.

---

## Usage

All commands are run from the web terminal.

### Listing Filters

- **List regions:**

    ```bash
    python medichaser.py list-filters regions
    ```

- **List specialties:**

    ```bash
    python medichaser.py list-filters specialties
    ```

- **List clinics** (example for Warsaw, Pediatrics):

    ```bash
    python medichaser.py list-filters clinics -r 204 -s 132
    ```

- **List doctors** (example for Warsaw, Pediatrics):

    ```bash
    python medichaser.py list-filters doctors -r 204 -s 132
    ```

### Finding Appointments

- **Basic search** (Pediatrician in Warsaw):

    ```bash
    python medichaser.py find-appointment -r 204 -s 132
    ```

- **Search with a date range**:

    ```bash
    python medichaser.py find-appointment -r 204 -s 132 -d 394 -f "2025-12-16" -e "2025-12-19"
    ```

- **Search in one clinic**:

    ```bash
    python medichaser.py find-appointment -r 204 -s 132 -c 49284
    ```

- **Search by language** (Ukrainian-speaking dental hygienist):

    ```bash
    python medichaser.py find-appointment -r 204 -s 112 -l 60
    ```

- **Continuous monitoring and notifications**:

    ```bash
    python medichaser.py find-appointment -r 204 -s 132 -i 15 -n gotify -t "Pediatra Warszawa"
    ```

    To run the monitoring process in the background within the web terminal, you can use `screen`:

    1. Start a new screen session:

        ```bash
        screen -S medichaser
        ```

    2. Run your command with the interval (`-i`) option.
    3. Detach from the session by pressing `Ctrl+A` then `D`. The command will keep running.
    4. To re-attach to the session later, run:

        ```bash
        screen -r medichaser
        ```

    For more information on using screen, check out this [guide](https://www.gnu.org/software/screen/manual/screen.html).

### Running Multiple Searches in Parallel

You can describe several appointment searches in a single TOML file and execute them in parallel. Notifications are sent only the first time a slot is seen, even if the same appointment reappears later.

1. Copy the example configuration and adjust it to your needs:

    ```bash
    cp appointments.example.toml appointments.toml
    $EDITOR appointments.toml
    ```

    Each `[[jobs]]` entry maps directly to the arguments of `find-appointment`. You can optionally add a `label` field to make log output easier to read. The optional `[settings]` table accepts `max_parallel`, which limits how many jobs run concurrently.

2. Start the parallel searcher:

    ```bash
    python medichaser.py find-appointments --config appointments.toml
    ```

    To override the concurrency defined in the file, pass `--max-parallel`:

    ```bash
    python medichaser.py find-appointments --config appointments.toml --max-parallel 2
    ```

All workers share an in-memory cache of delivered notifications, so you will only be alerted once per appointment slot.

---

## Notifications Setup

Add the required environment variables for your preferred service to the `.env` file.

### Gotify

- `GOTIFY_HOST`: Your server URL (e.g., `http://gotify.example.com:8080`).
- `GOTIFY_TOKEN`: Your app token.
- `GOTIFY_PRIORITY` (Optional): Default is `5`.

### Telegram

- `NOTIFIERS_TELEGRAM_TOKEN`: Your bot token.
- `NOTIFIERS_TELEGRAM_CHAT_ID`: The chat ID to send messages to.

### Pushover

- `NOTIFIERS_PUSHOVER_USER`: Your user key.
- `NOTIFIERS_PUSHOVER_TOKEN`: Your application API token.

### Pushbullet

- `NOTIFIERS_PUSHBULLET_TOKEN`: Your access token.

### Prowl

- `NOTIFIERS_PROWL_API_KEY`: Your API key.

### XMPP (Jabber)

- `NOTIFIERS_XMPP_JID`: Your full JID (`user@example.com`).
- `NOTIFIERS_XMPP_PASSWORD`: Your password.
- `NOTIFIERS_XMPP_RECEIVER`: The recipient's JID.

---

## Deploying to Fly.io

This repository includes a ready-to-use [`fly.toml`](./fly.toml). The configuration runs the web terminal on the `web` process and the parallel appointment watcher on the `watcher` process.

1. **Prepare your configuration locally.**

    ```bash
    cp appointments.example.toml appointments.toml
    $EDITOR appointments.toml
    ```

2. **Initialize the Fly application (without deploying yet):**

    ```bash
    fly launch --copy-config --no-deploy
    ```

3. **Create a persistent volume for tokens, logs, and configuration:**

    ```bash
    fly volumes create medichaser_data --size 1 --region <REGION>
    ```

4. **Store your Medicover credentials and notifier secrets:**

    ```bash
    fly secrets set MEDICOVER_USER="username" MEDICOVER_PASS="password"
    # Add additional notifier secrets as needed
    ```

5. **Deploy the application:**

    ```bash
    fly deploy --remote-only
    ```

6. **Upload the appointment configuration.** Open the web terminal served by the `web` process (`https://<app-name>.fly.dev`) and copy `appointments.toml` to `/app/data/appointments.toml` (the path referenced by `APPOINTMENTS_CONFIG`).

7. **Start the watcher process:**

    ```bash
    fly scale count watcher=1
    ```

    Adjust the count or the `max_parallel` value inside `appointments.toml` if you need to change concurrency later.

8. **Monitor the service:**

    ```bash
    fly logs --process watcher
    ```

You can customize the configuration path by changing the `APPOINTMENTS_CONFIG` environment variable in `fly.toml`.

---

## Security Considerations

The integrated `ttyd` web terminal provides convenient access to the container's command line. If you are hosting this service on a publicly accessible server, it is crucial to secure the web terminal to prevent unauthorized access.

You can secure `ttyd` by:

- **Using `ttyd`'s built-in authentication**: Change default CMD to enable basic authentication when running container.
- **Using a reverse proxy**: Place a reverse proxy like Nginx or Traefik in front of the `ttyd` service to handle authentication and SSL/TLS termination.

---

## Development

```bash
# 1. install poetry
poetry install
# 2. hack
# 3. lint directly or install pre-commit hooks with poetry run pre-commit install
poetry run pre-commit run -a
# 4. run tests
poetry run pytest
```

---

## Acknowledgements

This project stands on the shoulders of giants. Big thanks to the original authors and inspirations:

- [apqlzm/medihunter](https://github.com/apqlzm/medihunter)
- [SteveSteve24/MediCzuwacz](https://github.com/SteveSteve24/MediCzuwacz)
- [atais/medibot](https://github.com/atais/medibot)
