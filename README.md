# FuelTrack Central

Cloud-hosted companion to the FuelTrack station app: user accounts, a
station registry, hardware license issuance, and a per-station subscription
flag that station apps check in against periodically.

This is a separate, independently deployable project - it shares no code
with the station app at runtime (the license-serial algorithm in
`lib/license.js` is intentionally duplicated; see the comment there).

## Storage: Turso

Uses [Turso](https://turso.tech) (hosted libSQL) via `@libsql/client` -
`lib/db.js` talks to it exactly like local SQLite, so the same code works
against a `file:` URL for local dev and a real `libsql://...` database in
production. Set `TURSO_DATABASE_URL` and `TURSO_AUTH_TOKEN`; without them it
falls back to a local `central.db` file.

Turso's dashboard (turso.tech) can create a database and issue an auth
token entirely through the web UI - no CLI required (the CLI itself needs
WSL on Windows).

## Local run

```bash
npm install
npm run create-admin -- you@example.com "a strong password"
npm start   # -> http://localhost:4100
```

Log in at `/login` with the admin account you just created.

## What it does

- **Users**: email + password accounts, role `admin` or `owner`. Admins get
  the full dashboard; owners get a read-only view of their own station(s).
- **Stations**: each has a name, optional owner, optional address (just a
  label for the admin - the central server never talks to the station's
  dispensers directly), a subscription flag, and an API key (shown once at
  creation - store it, only its hash is kept).
- **License issuance**: paste in a station PC's hardware fingerprint (from
  `npm run fingerprint` in the station app) and get back the exact
  `sigma_123.lic` content for that machine - no need to run the station
  app's own `generate-license.js` locally anymore.
- **Check-in** (`POST /api/checkin`, station-authenticated with its API
  key, not a user session): returns the current subscription flag and
  records `last_checkin_at`/`last_checkin_ip`. This is what the station
  app's `lib/central.js` calls periodically.

## Deploying

Ships as a plain Node app (`Dockerfile` included). Deployed to
[Render](https://render.com)'s free tier (no card required) as a Docker
web service, since the database now lives in Turso rather than on local
disk - no persistent volume needed on the host at all.

Environment variables to set on the host:
- `TURSO_DATABASE_URL` - from the Turso dashboard
- `TURSO_AUTH_TOKEN` - generated from the Turso dashboard
- `PORT` - Render sets this automatically; the app respects it

**TLS**: this app speaks plain HTTP; Render terminates HTTPS automatically.

Render's free tier spins the service down after 15 minutes of inactivity
and takes about a minute to wake back up on the next request - fine for a
station checking in every few minutes, since a slightly slow check-in just
means that one check-in takes longer, not that it fails (the station app
caches the last known subscription status regardless).

```bash
docker build -t fueltrack-central .
docker run -p 4100:4100 -e TURSO_DATABASE_URL=... -e TURSO_AUTH_TOKEN=... fueltrack-central
```

## Wiring a station up to this

1. `npm run create-admin` once (above), log in.
2. Add a user for the station owner (Users section) if they need their own
   login - optional, not required for check-in to work.
3. Add the station (Stations section) - copy the API key shown, it's only
   displayed once.
4. In that station's `config.json`, add:
   ```json
   "central": {
     "url": "https://your-central-server.example.com",
     "stationId": "st_xxxxxxxx",
     "apiKey": "the key from step 3",
     "checkinIntervalMinutes": 5
   }
   ```
5. Restart the station app - it'll start checking in on that interval and
   cache the subscription flag locally, so it keeps working through
   central-server or network outages using the last known value.
6. Toggle the "Subscription" pill for that station any time to enable/
   disable local data saving on the station (live nozzle monitoring keeps
   working either way - only historical persistence is gated).
