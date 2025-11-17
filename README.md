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
