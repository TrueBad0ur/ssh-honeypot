# TryHackMe SSH Honeypot
SSH Honeypot that gathers attempted creds, IP addresses and versions.
The SSH server will either issue a warning, or drop the attacker into a fake shell.

## Loot File Format
The logging writes to an SQLite database at `db/honeypot.db`. The database and tables are created automatically on first run.

## Fake Shell
The fake shell will print a bash command not found error for every command entered, except exit.
You can enable logging of these commands with the -C flag.

## Database Viewer
Open `viewer/index.html` in a browser, then select your `honeypot.db` file to view and filter logins and commands.
