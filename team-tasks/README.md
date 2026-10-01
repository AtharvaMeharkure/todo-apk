# Team Tasks: Render + Android APK

Flask + SQLite backend (hosted on Render) and an Android app (APK) that opens it.

## Step 1: Host on Render
1. Create a GitHub repo and upload everything in this folder (this folder = repo root).
2. On render.com: New > Blueprint > pick your repo. Render reads `render.yaml`.
3. When asked for ADMIN_PASSWORD, enter a strong password (admin username is `admin`).
4. Wait for the deploy. Your URL looks like https://team-tasks-xxxx.onrender.com. Open it and sign in.

Cost: the Starter plan is required because SQLite needs a persistent disk (the free plan wipes the
database on every restart or sleep, so employee accounts would disappear). Don't run more than one instance.

## Step 2: Build the APK (no Android Studio needed)
1. In your GitHub repo: Actions > "Build Android APK" > Run workflow.
2. Paste your Render URL (https://...onrender.com) and run. It takes about 5 minutes.
3. Open the finished run, download the `team-tasks-apk` artifact, unzip it to get `app-debug.apk`.
4. Send the APK to phones. On Android, allow "install unknown apps" for the app you opened it from, then install.

The APK only loads your Render URL, so server updates show up in the app without rebuilding it.
Rebuild the APK only if your Render URL changes. It needs an internet connection.

## Run locally
    pip install -r requirements.txt
    ADMIN_PASSWORD="choose-one" python app.py        # http://localhost:5000

## Settings (environment variables)
ADMIN_PASSWORD (first run only), DB_PATH, PORT, HOST, TRUST_PROXY=1 (set on Render).
Forgot the admin password? Delete the database file on the disk (Render Shell: rm /var/data/tasks.db) and
restart; the admin is recreated from ADMIN_PASSWORD. This also removes all employees and tasks.

## API
POST /api/login, /api/logout; GET /api/me; GET/POST /api/employees, DELETE /api/employees/<id> (admin);
GET/POST /api/tasks; PATCH/DELETE /api/tasks/<id>. Send `Authorization: Bearer <token>`.
