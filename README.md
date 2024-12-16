# MediCzuwacz

Monitor new Medicover appointments with MediCzuwacz, designed to work with the latest authentication system (as of December 2024).

- Automate appointment monitoring
- Supports notifications via Gotify and other providers.
- Easy setup and automation with Docker.

 
---

## Configuration (One-Time Setup)
1. Copy the example environment file:
   ```bash
   cp .env.example .env
   ```
2. Fill in the `.env` file with your credentials.
3. Run the following command to build the Docker image:
    ```bash
    docker build --rm -t mediczuwacz .
    ```

---

## Usage

### Run with Parameters
#### Example 1: Search for an Appointment
For a pediatrician (`Pediatra`) in Warsaw:
```bash
docker run --rm --env-file=.env mediczuwacz find-appointment -r 204 -s 132 -f "2024-12-11"
```

#### Example 2: Search and Send Notifications
To search and send notifications via Gotify:
```bash
docker run --rm --env-file=.env mediczuwacz find-appointment -r 204 -s 132 -f "2024-12-11" -n gotify -t "Pediatra"
```

#### Example 3: Search for an Appointment in particular Clinic (Łukiska - 49284)
To search and send notifications via Gotify:
```bash
docker run --rm --env-file=.env mediczuwacz find-appointment -r 204 -s 132 -f "2024-12-11" -c 49284 -n gotify -t "Pediatra"
```


---

## How to Know IDs?
In commands, you use different IDs (e.g., `204` for Warsaw). How do you find other values?

Run the following commands:

- To list available regions:
  ```bash
  docker run --rm --env-file=.env mediczuwacz list-filters regions
  ```

- To list available specialties:
  ```bash
  docker run --rm --env-file=.env mediczuwacz list-filters specialties
  ```

- To list doctors for a specific region and specialty:
  ```bash
  docker run --rm --env-file=.env mediczuwacz list-filters doctors -r 204 -s 132
  ```

---

## Telegram Notifications
Use the Telegram app to send notifications to your channel by following these steps:

### Step 1: Create a Telegram Bot
Follow this guide to create a Telegram Bot: [Create Telegram Bot](https://gist.github.com/nafiesl/4ad622f344cd1dc3bb1ecbe468ff9f8a).

### Step 2: Update `.env`
Add the following lines to your `.env` file:
```bash
NOTIFIERS_TELEGRAM_CHAT_ID=111222333
NOTIFIERS_TELEGRAM_TOKEN=mySecretToken
```

### Step 3: Run the Command
Run the following command to send Telegram notifications:
```bash
docker run --rm --env-file=.env mediczuwacz find-appointment -r 204 -s 132 -f "2024-12-11" -n telegram -t "Pediatra"
```

---

## Automating the Script with CRON
### Step 1: Create a Bash Script
Create a script named `run_mediczuwacz.sh`:
```bash
#!/bin/bash
cd /home/projects/
docker run --rm --env-file=.env mediczuwacz find-appointment -r 204 -s 132 -f "2024-12-11" -n gotify -t "Pediatra"
```
Make the script executable:
```bash
chmod +x run_mediczuwacz.sh
```

### Step 2: Configure CRON
Set up a CRON job to check appointments every 10 minutes:
1. Edit the crontab:
   ```bash
   crontab -e
   ```
2. Add the following line:
   ```bash
   */10 * * * * /home/projects/mediczuwacz/run_mediczuwacz.sh >> /home/projects/mediczuwacz/cron_log.txt 2>&1
   ```


---

## Changelog

### v0.1 - 2024-12-11
- Repository initialized; created because the old Medihunter stopped working due to incompatibility with the new authentication system.

### v0.2 - 2024-12-13
- Added the `list-filters` command (by areqq).


---

## Acknowledgements
Special thanks to the following projects for their inspiration:
- [apqlzm/medihunter](https://github.com/apqlzm/medihunter)
- [atais/medibot](https://github.com/atais/medibot)


