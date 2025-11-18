# Automatisierte KAS-Backups

Dieses Repository enthält ein Skript, um Webspace-, MySQL- und IMAP-Postfach-Daten per All-Inkl KAS-API zu sichern. Die API wird direkt von `backup_kas.sh` angesprochen; eine separate Konfigurationsgenerierung ist nicht mehr nötig.

## Voraussetzungen
- SSH-Schlüssel unter `/root/.ssh/id_rsa` mit Zugriff auf den Zielserver (`${HOST}` im Skript).
- Installierte Werkzeuge: `bash`, `rsync`, `ssh`, `mysqldump`, `python3` (für die API-Auswertung) und `imapsync` für E-Mail-Backups.
- Für Maildir-Zielbackups zusätzlich `mbsync` (aus dem `isync`-Paket).
- Schreibrechte auf dem Ziel-Backup-Pfad (Standard: `/srv/backup`).

## Konfiguration
### Wichtige Umgebungsvariablen
- `BACKUP_PATH` (Standard: `/srv/backup`)
- `HOST` (Standard: `w018d9ee.kasserver.com`)
- `LOG_FILE` (Standard: `/var/log/kas-backup.log`)
- `KAS_CONFIG_FILE` (Standard: `/etc/backup_kas.conf`), zusätzliche statische Aufträge
- `ENABLE_KAS_API_BACKUP` (Standard: `0`)
- `KAS_LOGIN` / `KAS_AUTH_DATA` / `KAS_AUTH_TYPE` / `KAS_API_ENDPOINT` für API-Backups

### IMAP-Backup-Ziele
- `IMAP_SOURCE_HOST` (Standard: `imap.kasserver.com`)
- `IMAP_TARGET_HOST` (Pflicht für Mail-Backups)
- `IMAP_TARGET_USER_PREFIX` / `IMAP_TARGET_USER_SUFFIX` (optional, um Ziel-Logins zu formen)
- `IMAP_TARGET_PASSWORD` (optional, fällt sonst auf das Quell-Passwort zurück)
- `IMAP_TARGET_SSL_FLAGS` (Standard: `--ssl2`)
- `MAIL_BACKUP_STRATEGY` (Standard: `imapsync`; alternativ `maildir` für ein lokales Maildir-Ziel unter `${BACKUP_PATH}/mail/<adresse>` via `mbsync`)
- `MAILDIR_SSL_TYPE` (Standard: `IMAPS`, SSL-Vorgabe für `mbsync` beim Maildir-Backup)

Mit `MAIL_BACKUP_STRATEGY=maildir` landen alle Postfächer als Maildir unter `${BACKUP_PATH}/mail/<adresse>`. Das funktioniert ohne zweiten IMAP-Server und nutzt `mbsync`, um Ordnerstruktur und Nachrichten inkrementell zu spiegeln.

### KAS-API-gesteuerte Sicherung
Aktivieren Sie `ENABLE_KAS_API_BACKUP=1`, setzen Sie `KAS_LOGIN` und `KAS_AUTH_DATA` und rufen Sie das Skript auf. Es
- spiegelt alle FTP-Accounts (inkl. Unteraccounts) mit `rsync`,
- sichert alle Datenbanken via `mysqldump`,
- spiegelt jedes Postfach via `imapsync` auf den konfigurierten IMAP-Zielserver.

### Statische Konfiguration
- Hinterlegen Sie zusätzliche Sicherungen in `/etc/backup_kas.conf` oder einer eigenen Datei und setzen Sie `KAS_CONFIG_FILE` entsprechend.
- Liegt die Datei nicht unter `/etc/backup_kas.conf`, müssen Sie sie explizit über `KAS_CONFIG_FILE` setzen; die mitgelieferte Datei `etc/backup_kas.conf` dient nur als Muster und wird nicht automatisch geladen.
- Die Datei kann sowohl Funktionsaufrufe (z. B. `mirror ...`) als auch Variablen enthalten. Fehlende Pflichtwerte wie `KAS_LOGIN`/`KAS_AUTH_DATA` oder `IMAP_TARGET_HOST` werden bei interaktiven Aufrufen abgefragt.
- Beispiele für `mirror`- und `database_backup`-Aufrufe sowie konfigurierbare Variablen finden Sie in `etc/backup_kas.conf`.

### Geführtes Onboarding
Rufen Sie `./backup_kas.sh --onboarding` auf, um interaktiv die wichtigsten Variablen (z. B. `BACKUP_PATH`, `HOST`, `LOG_FILE`, IMAP-Zielwerte sowie API-Zugangsdaten) abzufragen und in `/etc/backup_kas.conf` zu speichern. Läuft das Skript interaktiv ohne vorhandene Konfiguration, startet das Onboarding automatisch.

## Backups ausführen
```bash
ENABLE_KAS_API_BACKUP=1 \
KAS_LOGIN=kas12345 \
KAS_AUTH_DATA=geheim \
IMAP_TARGET_HOST=backup.imap.local \
./backup_kas.sh
```

Alle Backup-Aktionen werden an `${LOG_FILE}` angehängt. Das Skript legt die notwendigen Unterordner in `${BACKUP_PATH}` an und wartet zwischen den Schritten kurze Pausen ein, um Lastspitzen zu vermeiden.

### Skriptoptionen
- `-h, --help`: Zeigt eine kurze Übersicht der verfügbaren Optionen.
- `-q, --quiet`: Unterdrückt Ausgaben auf STDOUT und schreibt ausschließlich ins Logfile.
- `--cron`: Aktiviert einen stillen Modus für Cron-Jobs (setzt automatisch `--quiet`).

Beispiel für den Aufruf im Cron-Modus:

```bash
CRON_MODE=1 ./backup_kas.sh --cron
```

## Haftungsausschluss
Die Beispielkonfiguration enthält Platzhalter-Zugangsdaten. Ersetzen Sie diese durch Ihre produktiven Werte und bewahren Sie sensible Informationen sicher auf.
