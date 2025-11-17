#!/bin/bash

set -euo pipefail

# Konfigurationsvariablen
BACKUP_PATH=${BACKUP_PATH:-"/srv/backup"}
HOST=${HOST:-"w018d9ee.kasserver.com"}
CONFIG_FILE=${KAS_CONFIG_FILE:-"/etc/backup_kas.conf"}
LOG_FILE=${LOG_FILE:-"/var/log/kas-backup.log"}
ENABLE_KAS_API_BACKUP=${ENABLE_KAS_API_BACKUP:-0}

# KAS API-Zugänge
KAS_API_ENDPOINT=${KAS_API_ENDPOINT:-"https://kasapi.kasserver.com/soap/v2.0/"}
KAS_LOGIN=${KAS_LOGIN:-""}
KAS_AUTH_DATA=${KAS_AUTH_DATA:-""}
KAS_AUTH_TYPE=${KAS_AUTH_TYPE:-"plain"}

# IMAP-Backup Einstellungen
IMAP_SOURCE_HOST=${IMAP_SOURCE_HOST:-"imap.kasserver.com"}
IMAP_TARGET_HOST=${IMAP_TARGET_HOST:-""}
IMAP_TARGET_USER_PREFIX=${IMAP_TARGET_USER_PREFIX:-""}
IMAP_TARGET_USER_SUFFIX=${IMAP_TARGET_USER_SUFFIX:-""}
IMAP_TARGET_PASSWORD=${IMAP_TARGET_PASSWORD:-""}
IMAP_TARGET_SSL_FLAGS=${IMAP_TARGET_SSL_FLAGS:---ssl2}

export date=$(date "+%Y-%m-%d")

function mkdir_cd {
  echo -e "#####################################################################\n# mkdir_cd $1 \n###############################################################"
  if [ ! -d "${BACKUP_PATH}/$1" ]; then
    mkdir -p "${BACKUP_PATH}/$1"
  fi
  cd "${BACKUP_PATH}/$1" || exit 1
}

function database_backup {
  echo "Database ${3}"
  mkdir_cd db

  backupfile="${1}-${2}-${3}.sql"
  echo ssh -i "/root/.ssh/id_rsa" -o StrictHostKeyChecking=no "${1}@${HOST}" mysqldump "-u${2}" "-p${4}" "${3}" \>"${backupfile}"
  ssh -i "/root/.ssh/id_rsa" -o StrictHostKeyChecking=no "${1}@${HOST}" mysqldump "-u${2}" "-p${4}" "${3}" >"${backupfile}" 2>>"${LOG_FILE}"
  ls -la "${backupfile}"
  tail -n 1 "${backupfile}"
  echo "warte 60 sec"
  sleep 60
}

function mirror {
  echo -e "#####################################################################\n# mirror $1 \n###############################################################"
  rsync -av --delete -e "ssh -i /root/.ssh/id_rsa  -o StrictHostKeyChecking=no" "ssh-$1@${HOST}:/www/htdocs/${2}" . 2>&1 | tee -a "${LOG_FILE}"
  echo "warte 60 sec"
  sleep 60
}

function mail_backup {
  local login=$1
  local password=$2
  local address=$3

  if ! command -v imapsync >/dev/null 2>&1; then
    echo "imapsync ist nicht installiert, Mail-Backup wird übersprungen." >&2
    return 0
  fi

  if [ -z "${IMAP_TARGET_HOST}" ]; then
    echo "IMAP_TARGET_HOST ist nicht gesetzt, Mail-Backup wird übersprungen." >&2
    return 0
  fi

  mkdir_cd mail
  local target_user="${IMAP_TARGET_USER_PREFIX}${address}${IMAP_TARGET_USER_SUFFIX}"
  local target_password="${IMAP_TARGET_PASSWORD:-${password}}"
  local logfile="${BACKUP_PATH}/mail/${address}.log"

  echo -e "#####################################################################\n# imapsync ${address} \n###############################################################" | tee -a "${LOG_FILE}"
  imapsync \
    --host1 "${IMAP_SOURCE_HOST}" --user1 "${address}" --password1 "${password}" --ssl1 \
    --host2 "${IMAP_TARGET_HOST}" --user2 "${target_user}" --password2 "${target_password}" ${IMAP_TARGET_SSL_FLAGS} \
    --usecache --nofoldersizes --tmpdir /tmp --logfile "${logfile}" 2>>"${LOG_FILE}"
  echo "warte 30 sec"
  sleep 30
}

function load_config {
  local config_path=$1
  if [ -f "${config_path}" ]; then
    # shellcheck source=/dev/null
    . "${config_path}"
  else
    echo "Konfigurationsdatei ${config_path} wurde nicht gefunden, statische Aufträge werden übersprungen." >&2
  fi
}

function kas_api_request() {
  local action=$1
  shift
  local data=("-d" "kas_login=${KAS_LOGIN}" "-d" "kas_auth_type=${KAS_AUTH_TYPE}" "-d" "kas_auth_data=${KAS_AUTH_DATA}" "-d" "kas_action=${action}")
  for param in "$@"; do
    data+=("-d" "kas_params[${param%%=*}]=${param#*=}")
  done
  curl -sS "${KAS_API_ENDPOINT}" "${data[@]}"
}

function parse_json() {
  local json_input=$1
  local python_filter=$2
  python3 - "$python_filter" <<'PY'
import json, sys
payload = sys.stdin.read()
filter_expr = sys.argv[1]
try:
    data = json.loads(payload)
except json.JSONDecodeError as exc:
    sys.stderr.write(f"Konnte API-Antwort nicht parsen: {exc}\n")
    sys.exit(1)

def dig(obj, path):
    cur = obj
    for part in path:
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return []
    return cur

result = dig(data, ["Response", "Result", "item"])
if not result:
    result = dig(data, ["Response", "Result", "items"])
if not result and isinstance(dig(data, ["Response", "Result"]), list):
    result = dig(data, ["Response", "Result"])
if not isinstance(result, list):
    sys.stderr.write("API-Antwort enthält keine Liste mit 'item' oder 'items'.\n")
    sys.exit(1)

for entry in result:
    value = entry
    for part in filter_expr.split('.'):
        if isinstance(value, dict):
            value = value.get(part)
        else:
            value = None
        if value is None:
            break
    if value is not None:
        print(value)
PY
}

function kas_api_backup() {
  if [ -z "${KAS_LOGIN}" ] || [ -z "${KAS_AUTH_DATA}" ]; then
    echo "KAS_LOGIN und KAS_AUTH_DATA müssen gesetzt sein, um die API zu nutzen." >&2
    exit 1
  fi

  echo -e "#####################################################################\n# KAS API Backup \n###############################################################" | tee -a "${LOG_FILE}"

  ftp_json=$(kas_api_request get_accounts "type=ftp")
  db_json=$(kas_api_request get_databases)
  mail_json=$(kas_api_request get_mailaccounts)

  mapfile -t ftp_logins < <(echo "${ftp_json}" | parse_json - "login")
  mapfile -t ftp_dirs < <(echo "${ftp_json}" | parse_json - "dir")

  if [ "${#ftp_logins[@]}" -ne "${#ftp_dirs[@]}" ]; then
    echo "Anzahl der FTP-Logins unterscheidet sich von der Anzahl der Verzeichnisse." >&2
    exit 1
  fi

  for i in "${!ftp_logins[@]}"; do
    login="${ftp_logins[$i]}"
    dir="${ftp_dirs[$i]#/www/htdocs/}"
    mirror "${login}" "${dir}"
  done

  mapfile -t db_users < <(echo "${db_json}" | parse_json - "db_username")
  mapfile -t db_names < <(echo "${db_json}" | parse_json - "db_name")
  mapfile -t db_passwords < <(echo "${db_json}" | parse_json - "db_password")

  if [ "${#db_users[@]}" -ne "${#db_names[@]}" ] || [ "${#db_users[@]}" -ne "${#db_passwords[@]}" ]; then
    echo "Datenbankeinträge sind unvollständig. Prüfen Sie die API-Antwort." >&2
    exit 1
  fi

  for i in "${!db_users[@]}"; do
    login="${db_users[$i]}"
    name="${db_names[$i]}"
    password="${db_passwords[$i]}"
    database_backup "ssh-${login}" "${login}" "${name}" "${password}"
  done

  mapfile -t mail_logins < <(echo "${mail_json}" | parse_json - "mail_login")
  mapfile -t mail_passwords < <(echo "${mail_json}" | parse_json - "mail_password")
  mapfile -t mail_addresses < <(echo "${mail_json}" | parse_json - "mail_email")

  if [ "${#mail_logins[@]}" -eq 0 ]; then
    echo "Keine Mailkonten in der API-Antwort gefunden." | tee -a "${LOG_FILE}"
  fi

  if [ "${#mail_logins[@]}" -ne "${#mail_passwords[@]}" ] || [ "${#mail_logins[@]}" -ne "${#mail_addresses[@]}" ]; then
    echo "Mailkonto-Antwort ist unvollständig. Prüfen Sie die API-Antwort." >&2
    exit 1
  fi

  for i in "${!mail_logins[@]}"; do
    address="${mail_addresses[$i]}"
    password="${mail_passwords[$i]}"
    mail_backup "${mail_logins[$i]}" "${password}" "${address}"
  done
}

echo -e ":::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::\n$(date)\n:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::" >>"${LOG_FILE}"

mkdir_cd kas/
mkdir_cd db/

if [ "${ENABLE_KAS_API_BACKUP}" -eq 1 ]; then
  kas_api_backup
fi

load_config "${CONFIG_FILE}"
