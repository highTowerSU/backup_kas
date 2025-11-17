# Automatisierte KAS-Backups

Dieses Repository enthält ein einfaches Skript, um Webspace- und MySQL-Datenbanken
auf Basis der All-Inkl KAS-API zu sichern.

## Verwendung

1. Legen Sie den Zielpfad und den Zielhost über Umgebungsvariablen fest (optional):
   - `BACKUP_PATH` (Standard: `/srv/backup`)
   - `HOST` (Standard: `w018d9ee.kasserver.com`)
   - `LOG_FILE` (Standard: `/var/log/kas-backup.log`)

2. Aktivieren Sie die automatische Konfiguration per KAS-API:
   - Setzen Sie `ENABLE_KAS_API_BACKUP=1`.
   - Stellen Sie die API-Zugangsdaten bereit: `KAS_LOGIN` und `KAS_AUTH_DATA`.
   - Optional können Sie `KAS_API_ENDPOINT` und `KAS_AUTH_TYPE` setzen (Standard: `https://kasapi.kasserver.com/soap/v2.0/` bzw. `plain`).

3. Falls keine API genutzt werden soll, tragen Sie die gewünschten Sicherungen in
   `/etc/backup_kas.conf` oder in eine eigene Datei ein und setzen Sie
   `KAS_CONFIG_FILE` entsprechend. Beispiele finden Sie in `etc/backup_kas.conf`.

4. Starten Sie das Backup:

```bash
ENABLE_KAS_API_BACKUP=1 KAS_LOGIN=kas12345 KAS_AUTH_DATA=geheim ./backup_kas.sh
```

Das Skript `kas_api_generate_config.sh` ruft dazu die KAS-API auf, generiert eine
Konfigurationsdatei mit `mirror`- und `database_backup`-Aufrufen und führt diese
anschließend über `backup_kas.sh` aus.

## Hinweise

- Für die API-Auswertung wird Python 3 benötigt.
- Die API-Antworten müssen die Felder `login`, `dir`, `db_username`, `db_name`
  und `db_password` enthalten. Bei abweichenden Feldnamen kann die Funktion
  `parse_json` in `kas_api_generate_config.sh` angepasst werden.
- Die SSH-Schlüssel werden wie zuvor unter `/root/.ssh/id_rsa` erwartet.
# backup_kas

Bash-basiertes Hilfsskript, um Datenbanken und Webverzeichnisse von einem Kasserver-System auf einen Backup-Host zu spiegeln.

## Inhalte
- `backup_kas.sh`: Kernskript, das Verzeichnisse erstellt, die Verbindung zum Host aufbaut und rsync/mysqldump-Backups ausführt.
- `etc/backup_kas.conf`: Beispielhafte Konfigurationsdatei, die projektspezifische Backup-Befehle enthält.
- `LICENSE`: Lizenzinformationen für dieses Repository.

## Voraussetzungen
- SSH-Schlüssel unter `/root/.ssh/id_rsa` mit Zugriff auf den Zielserver (`${HOST}` im Skript).
- Schreibrechte auf dem Ziel-Backup-Pfad (Standard: `/srv/backup`).
- Installierte Werkzeuge: `bash`, `rsync`, `ssh`, `mysqldump`.

## Verwendung
1. Passen Sie die Variablen `BACKUP_PATH` und `HOST` in `backup_kas.sh` an Ihre Umgebung an.
2. Ergänzen Sie `etc/backup_kas.conf` mit den gewünschten `mirror`- und `database_backup`-Aufrufen.
3. Stellen Sie sicher, dass das Skript ausführbar ist:
   ```bash
   chmod +x backup_kas.sh
   ```
4. Starten Sie das Backup (typischerweise via Cron oder manuell):
   ```bash
   ./backup_kas.sh
   ```

## Hinweis zur Protokollierung
Alle Backup-Aktionen werden an `/var/log/kas-backup.log` angehängt. Nutzen Sie das Log, um Fehler und Durchläufe nachzuvollziehen.

## Haftungsausschluss
Die Beispielkonfiguration enthält Platzhalter-Zugangsdaten. Ersetzen Sie diese durch Ihre produktiven Werte und bewahren Sie sensible Informationen sicher auf.
