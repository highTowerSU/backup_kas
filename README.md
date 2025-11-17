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
