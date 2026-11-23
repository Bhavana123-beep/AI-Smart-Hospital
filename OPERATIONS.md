# Appointment reminder scheduler

The Flask app creates at most one in-app reminder for each appointment when it falls within the next 24 hours. The unique database constraint makes repeated runs safe. Patients can read reminders from their dashboard's Notifications page.

For Render, configure the web service and the `smart-hospital-appointment-reminders` Cron service with the same randomly generated `REMINDER_JOB_TOKEN`. Set `REMINDER_WEB_URL` on the Cron service to the public HTTPS base URL of the web service (for example, `https://your-service.onrender.com`). Set `HOSPITAL_TIMEZONE` on the web service to the hospital's IANA timezone; the default is `Asia/Kolkata`.

The Cron service calls the protected live web endpoint, which processes reminders against the web service's configured SQLite database. Render Cron services have a separate filesystem and do not share a persistent disk with web services; this design avoids writing reminders to a separate SQLite file. The endpoint returns 503 until the token is configured.

For local manual operation, activate the project virtual environment and run `flask --app app process-appointment-reminders`. Schedule that command with a persistent host scheduler if desired. Do not run it concurrently against a different database file.

## Production startup requirements

The `Procfile` sets `APP_ENV=production`. Before starting the web process, configure `SECRET_KEY` and an absolute `DATABASE_PATH` pointing to the existing SQLite database file on persistent storage. Production startup intentionally fails if either the secret or the database path/file is missing; this prevents weak development sessions and accidental creation of an empty database. On Render, mount persistent storage for the web service and set `DATABASE_PATH` to the existing file on that mount. Keep the Cron service pointed at the web service with `REMINDER_WEB_URL` and the shared `REMINDER_JOB_TOKEN`.

The current `render.yaml` defines the Cron service only. Configure the web service's persistent disk and environment variables in the existing Render service settings before deploying. Back up the existing database and validate the mounted path before changing the live setting.
