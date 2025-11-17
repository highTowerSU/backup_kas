#!/bin/bash

set -euo pipefail

# Standardoptionen
QUIET=0
CRON_MODE=0

function usage {
  cat <<'EOF'
Verwendung: backup_kas.sh [OPTIONEN]

Optionen:
  -h, --help     Zeigt diese Hilfe an und beendet sich.
  -q, --quiet    Unterdrückt Ausgabe auf STDOUT und schreibt nur ins Log.
      --cron     Aktiviert einen stillen Modus für Cron-Jobs (setzt --quiet).
EOF
}

function parse_args {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      -h|--help)
        usage
        exit 0
        ;;
      -q|--quiet)
        QUIET=1
        ;;
      --cron)
        CRON_MODE=1
        QUIET=1
        ;;
      *)
        echo "Unbekannte Option: $1" >&2
        usage
        exit 1
        ;;
    esac
    shift
  done
}

parse_args "$@"

# Konfigurationsvariablen
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
DEFAULT_CONFIG_FILE="/etc/backup_kas.conf"
BACKUP_PATH=${BACKUP_PATH:-"/srv/backup"}
HOST=${HOST:-"w018d9ee.kasserver.com"}
CONFIG_FILE=${KAS_CONFIG_FILE:-"${DEFAULT_CONFIG_FILE}"}
LOCAL_CONFIG_FILE="${SCRIPT_DIR}/etc/backup_kas.conf"
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
MAIL_BACKUP_STRATEGY=${MAIL_BACKUP_STRATEGY:-"imapsync"}
MAILDIR_SSL_TYPE=${MAILDIR_SSL_TYPE:-"IMAPS"}

function prompt_for_value {
  local var_name=$1
  local prompt=$2
  local silent=${3:-0}
  local allow_empty=${4:-0}
  local current_value=${!var_name-}

  if [ -n "${current_value}" ]; then
    return
  fi

  if [ ! -t 0 ]; then
    echo "${var_name} ist nicht gesetzt und es steht kein TTY für eine Eingabe zur Verfügung." >&2
    exit 1
  fi

  if [ "${silent}" -eq 1 ]; then
    read -r -s -p "${prompt}: " current_value
    echo
  else
    read -r -p "${prompt}: " current_value
  fi

  if [ -z "${current_value}" ] && [ "${allow_empty}" -eq 0 ]; then
    echo "${var_name} wurde nicht gesetzt. Vorgang abgebrochen." >&2
    exit 1
  fi

  printf -v "${var_name}" '%s' "${current_value}"
  export "${var_name}"
}

function log_line {
  local message=$1
  if [ "$QUIET" -eq 1 ]; then
    echo -e "$message" >>"${LOG_FILE}"
  else
    echo -e "$message" | tee -a "${LOG_FILE}"
  fi
}

export date=$(date "+%Y-%m-%d")

function mkdir_cd {
  log_line "#####################################################################\n# mkdir_cd $1 \n###############################################################"
  if [ ! -d "${BACKUP_PATH}/$1" ]; then
    mkdir -p "${BACKUP_PATH}/$1"
  fi
  cd "${BACKUP_PATH}/$1" || exit 1
}

function database_backup {
  log_line "Database ${3}"
  mkdir_cd db

  backupfile="${1}-${2}-${3}.sql"
  log_line "ssh -i \"/root/.ssh/id_rsa\" -o StrictHostKeyChecking=no \"${1}@${HOST}\" mysqldump \"-u${2}\" \"-p${4}\" \"${3}\" >\"${backupfile}\""
  ssh -i "/root/.ssh/id_rsa" -o StrictHostKeyChecking=no "${1}@${HOST}" mysqldump "-u${2}" "-p${4}" "${3}" >"${backupfile}" 2>>"${LOG_FILE}"
  if [ "$QUIET" -eq 1 ]; then
    ls -la "${backupfile}" >>"${LOG_FILE}"
    tail -n 1 "${backupfile}" >>"${LOG_FILE}"
  else
    ls -la "${backupfile}"
    tail -n 1 "${backupfile}"
  fi
  log_line "warte 60 sec"
  sleep 60
}

function mirror {
  log_line "#####################################################################\n# mirror $1 \n###############################################################"
  if [ "$QUIET" -eq 1 ]; then
    rsync -av --delete -e "ssh -i /root/.ssh/id_rsa  -o StrictHostKeyChecking=no" "ssh-$1@${HOST}:/www/htdocs/${2}" . >>"${LOG_FILE}" 2>&1
  else
    rsync -av --delete -e "ssh -i /root/.ssh/id_rsa  -o StrictHostKeyChecking=no" "ssh-$1@${HOST}:/www/htdocs/${2}" . 2>&1 | tee -a "${LOG_FILE}"
  fi
  log_line "warte 60 sec"
  sleep 60
}

function mail_backup {
  local login=$1
  local password=$2
  local address=$3

  case "${MAIL_BACKUP_STRATEGY}" in
    imapsync)
      if ! command -v imapsync >/dev/null 2>&1; then
        echo "imapsync ist nicht installiert, Mail-Backup wird übersprungen." >&2
        return 0
      fi

      prompt_for_value "IMAP_TARGET_HOST" "IMAP_TARGET_HOST (Ziel-IMAP-Server)"
      if [ -z "${IMAP_TARGET_PASSWORD-}" ] && [ -t 0 ]; then
        prompt_for_value "IMAP_TARGET_PASSWORD" "IMAP_TARGET_PASSWORD (Ziel-Passwort, leer für Quellpasswort)" 1 1
      fi

      mkdir_cd mail
      local target_user="${IMAP_TARGET_USER_PREFIX}${address}${IMAP_TARGET_USER_SUFFIX}"
      local target_password="${IMAP_TARGET_PASSWORD:-${password}}"
      local logfile="${BACKUP_PATH}/mail/${address}.log"

      log_line "#####################################################################\n# imapsync ${address} \n#######################################################"
      imapsync \
        --host1 "${IMAP_SOURCE_HOST}" --user1 "${address}" --password1 "${password}" --ssl1 \
        --host2 "${IMAP_TARGET_HOST}" --user2 "${target_user}" --password2 "${target_password}" ${IMAP_TARGET_SSL_FLAGS} \
        --usecache --nofoldersizes --tmpdir /tmp --logfile "${logfile}" 2>>"${LOG_FILE}"
      log_line "warte 30 sec"
      sleep 30
      ;;
    maildir)
      if ! command -v mbsync >/dev/null 2>&1; then
        echo "mbsync ist nicht installiert, Maildir-Backup wird übersprungen." >&2
        return 0
      fi

      mkdir_cd mail
      local maildir_path="${BACKUP_PATH}/mail/${address}"
      local mbsync_config
      mbsync_config=$(mktemp)

      cat >"${mbsync_config}" <<EOF
IMAPAccount source
Host ${IMAP_SOURCE_HOST}
User ${address}
Pass ${password}
SSLType ${MAILDIR_SSL_TYPE}

IMAPStore source-remote
Account source

MaildirStore source-local
Path ${maildir_path}/
Inbox ${maildir_path}/Inbox
SubFolders Verbatim

Channel backup
Master :source-remote:
Slave :source-local:
Patterns *
Create Slave
SyncState *
EOF

      mkdir -p "${maildir_path}"
      log_line "#####################################################################\n# mbsync ${address} -> Maildir \n##################################################"

      if [ "$QUIET" -eq 1 ]; then
        mbsync -c "${mbsync_config}" backup >>"${LOG_FILE}" 2>&1
      else
        mbsync -c "${mbsync_config}" backup 2>&1 | tee -a "${LOG_FILE}"
      fi

      rm -f "${mbsync_config}"
      log_line "warte 30 sec"
      sleep 30
      ;;
    *)
      echo "Unbekannte MAIL_BACKUP_STRATEGY: ${MAIL_BACKUP_STRATEGY}" >&2
      return 1
      ;;
  esac
}

function load_config {
  local config_path=$1
  local fallback_path=$2

  if [ -f "${config_path}" ]; then
    # shellcheck source=/dev/null
    . "${config_path}"
    return
  fi

  if [ -z "${KAS_CONFIG_FILE-}" ] && [ -f "${fallback_path}" ]; then
    echo "Konfigurationsdatei ${config_path} wurde nicht gefunden, verwende ${fallback_path}." >&2
    # shellcheck source=/dev/null
    . "${fallback_path}"
    return
  fi

  echo "Konfigurationsdatei ${config_path} wurde nicht gefunden, statische Aufträge werden übersprungen." >&2
}

function ensure_kas_api_credentials {
  prompt_for_value "KAS_LOGIN" "KAS_LOGIN (KAS-Benutzername)"
  prompt_for_value "KAS_AUTH_DATA" "KAS_AUTH_DATA (API-Passwort)" 1
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
  ensure_kas_api_credentials

  log_line "#####################################################################\n# KAS API Backup \n###############################################################"

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

  if [ "${#mail_logins[@]}" -ne "${#mail_passwords[@]}" ] || [ "${#mail_logins[@]}" -ne "${#mail_addresses[@]}" ]; then
    echo "Mailkonto-Antwort ist unvollständig. Prüfen Sie die API-Antwort." >&2
    exit 1
  fi

  if [ "${#mail_logins[@]}" -eq 0 ]; then
    log_line "Keine Mailkonten in der API-Antwort gefunden."
  fi

  for i in "${!mail_logins[@]}"; do
    address="${mail_addresses[$i]}"
    password="${mail_passwords[$i]}"
    mail_backup "${mail_logins[$i]}" "${password}" "${address}"
  done
}

load_config "${CONFIG_FILE}" "${LOCAL_CONFIG_FILE}"

log_line ":::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
$(date)
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::"

if [ "$CRON_MODE" -eq 1 ]; then
  log_line "Cron-Modus aktiv: Ausgabe erfolgt ausschließlich im Log (${LOG_FILE})."
fi

mkdir_cd kas/
mkdir_cd db/

if [ "${ENABLE_KAS_API_BACKUP}" -eq 1 ]; then
  kas_api_backup
fi
