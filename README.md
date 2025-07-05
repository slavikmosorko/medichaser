# Why forked

- added refresh token
- support to mfa
- run in web terminal - https://github.com/tsl0922/ttyd - this allows to remotely control this if hosted somewhere.

# Medichaser

Easily track when your Medicover doctor has open appointments.

- Automatically logs in to your Medicover account
- Checks for new available visits with selected doctors, clinics, or specialties
- Sends instant notifications (Gotify, Telegram, and more)
- Simple to set up and automate using Docker

---

## Configuration (One-Time Setup)

1. Copy the example environment file:
   ```bash
   cp .env.example .env
   ```
2. Fill in the `.env` file with your credentials.
3. Run following command to run docker compose:
   ```bash
   docker compose up -d
   ```
4. Visit http://localhost:7681 - integrated web terminal

---

## Usage

### Run with Parameters

#### Example 1: Search for an Appointment

For a pediatrician (`Pediatra`) in Warsaw:

```bash
python medichaser.py find-appointment -r 204 -s 132 -f "2024-12-11"
```

#### Example 2: Search and Send Notifications

To search and send notifications via Gotify:

```bash
python medichaser.py find-appointment -r 204 -s 132 -f "2024-12-11" -n gotify -t "Pediatra"
```

#### Example 3: Search for an Appointment in particular Clinic (Łukiska - 49284)

To search and send notifications via Gotify:

```bash
python medichaser.py find-appointment -r 204 -s 132 -f "2024-12-11" -c 49284 -n gotify -t "Pediatra"
```

#### Example 4: Search for a Specific Doctor and set End date

Use `-d` param:

```bash
python medichaser.py find-appointment -r 204 -s 132 -d 394 -f "2024-12-16" -e "2024-12-19"
```

#### Example 5: Search for a Dental Hygienist who speaks ukrainian

Use `-l` param:

```bash
python medichaser.py find-appointment -r 204 -s 112 -l 60
```

#### Example 6: start once and check for new Appointments every 10 minutes

```bash
python medichaser.py find-appointment -r 204 -s 112 -i 10
```

---

## How to Know IDs?

In commands, you use different IDs (e.g., `204` for Warsaw). How do you find other values?

Run the following commands:

- To list available regions:

  ```bash
  python medichaser.py list-filters regions
  ```

- To list available specialties:

  ```bash
  python medichaser.py list-filters specialties
  ```

- To list clinics for a specific region and specialty:

  ```bash
  python medichaser.py list-filters clinics -r 204 -s 132
  ```

- To list doctors for a specific region and specialty:
  ```bash
  python medichaser.py list-filters doctors -r 204 -s 132
  ```








---

## Acknowledgements

Special thanks to the following projects for their inspiration:

- [apqlzm/medihunter](https://github.com/apqlzm/medihunter)
- [SteveSteve24/MediCzuwacz](https://github.com/SteveSteve24/MediCzuwacz)
- [atais/medibot](https://github.com/atais/medibot)
