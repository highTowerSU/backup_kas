# Automatisierte KAS-Backups

Dieses Repository enthält Skripte, um Webspace- und MySQL-Datenbanken per All-Inkl KAS-API oder statischer Konfiguration zu sichern. Optional können IMAP-Postfächer mit `imapsync` auf einen zweiten Mailserver gespiegelt werden.

## Voraussetzungen
- SSH-Schlüssel unter `/root/.ssh/id_rsa` mit Zugriff auf den Zielserver (`${HOST}` im Skript).
- Installierte Werkzeuge: `bash`, `rsync`, `ssh`, `mysqldump`, `python3` (für die API-Auswertung) und optional `imapsync` für E-Mail-Backups.
- Schreibrechte auf dem Ziel-Backup-Pfad (Standard: `/srv/backup`).

## Konfiguration
### Wichtige Umgebungsvariablen
- `BACKUP_PATH` (Standard: `/srv/backup`)
- `HOST` (Standard: `w018d9ee.kasserver.com`)
- `LOG_FILE` (Standard: `/var/log/kas-backup.log`)
- `KAS_CONFIG_FILE` (Standard: `/etc/backup_kas.conf`)
- `GENERATED_CONFIG` (Standard: `/tmp/kas_backup_api.sh`)

### KAS-API-gesteuerte Sicherung
1. Aktivieren Sie die automatische Konfiguration: `ENABLE_KAS_API_BACKUP=1`.
2. Stellen Sie die API-Zugangsdaten bereit: `KAS_LOGIN` und `KAS_AUTH_DATA`.
3. Optional: `KAS_API_ENDPOINT` (Standard: `https://kasapi.kasserver.com/soap/v2.0/`) und `KAS_AUTH_TYPE` (Standard: `plain`).
4. Das Skript `kas_api_generate_config.sh` erstellt daraus eine Konfigurationsdatei mit `mirror`- und `database_backup`-Aufrufen, die anschließend von `backup_kas.sh` abgearbeitet wird.

### Statische Konfiguration
- Hinterlegen Sie gewünschte Sicherungen in `/etc/backup_kas.conf` oder einer eigenen Datei und setzen Sie `KAS_CONFIG_FILE` entsprechend.
- Beispiele für `mirror`- und `database_backup`-Aufrufe finden Sie in `etc/backup_kas.conf`.

## Backups ausführen
```bash
ENABLE_KAS_API_BACKUP=1 KAS_LOGIN=kas12345 KAS_AUTH_DATA=geheim ./backup_kas.sh
```

Alle Backup-Aktionen werden an `${LOG_FILE}` angehängt. Das Skript legt die notwendigen Unterordner in `${BACKUP_PATH}` an und wartet zwischen den Schritten kurze Pausen ein, um Lastspitzen zu vermeiden.

## E-Mail-Backups mit imapsync
Nutzen Sie `imapsync`, um jedes Postfach auf einen separaten IMAP-Server oder ein Archivkonto zu spiegeln. Ein einfaches Beispiel:

```bash
imapsync \
  --host1 mail.example.com --user1 mailbox@example.com --password1 'QUELLE_PASSWORT' --ssl1 \
  --host2 backup.imap.local --user2 mailbox@example.com --password2 'BACKUP_PASSWORT' --ssl2 \
  --usecache --nofoldersizes --tmpdir /tmp \
  --logfile "${BACKUP_PATH}/mail/mailbox@example.com.log"
```

- Wiederholen Sie den Aufruf pro Postfach (z. B. als Cronjob) und passen Sie Hostnamen sowie Zugangsdaten an.
- Der Zielserver sollte ein dediziertes Backup-IMAP-Konto bereitstellen, damit keine produktiven Postfächer überschrieben werden.

## Haftungsausschluss
Die Beispielkonfiguration enthält Platzhalter-Zugangsdaten. Ersetzen Sie diese durch Ihre produktiven Werte und bewahren Sie sensible Informationen sicher auf.
