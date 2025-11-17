#!/bin/bash

# Liest alle Kunden- und Datenbank-Informationen per KAS-API aus und erzeugt
# eine ausführbare Konfiguration für backup_kas.sh.

set -euo pipefail

OUTPUT_FILE=${1:-/tmp/kas_backup_api.sh}
API_ENDPOINT=${KAS_API_ENDPOINT:-"https://kasapi.kasserver.com/soap/v2.0/"}
KAS_LOGIN=${KAS_LOGIN:-""}
KAS_AUTH_DATA=${KAS_AUTH_DATA:-""}
KAS_AUTH_TYPE=${KAS_AUTH_TYPE:-"plain"}

if [ -z "${KAS_LOGIN}" ] || [ -z "${KAS_AUTH_DATA}" ]; then
  echo "KAS_LOGIN und KAS_AUTH_DATA müssen gesetzt sein, um die API zu nutzen." >&2
  exit 1
fi

function kas_api_request() {
  local action=$1
  shift
  local data=("-d" "kas_login=${KAS_LOGIN}" "-d" "kas_auth_type=${KAS_AUTH_TYPE}" "-d" "kas_auth_data=${KAS_AUTH_DATA}" "-d" "kas_action=${action}")
  for param in "$@"; do
    data+=("-d" "kas_params[${param%%=*}]=${param#*=}")
  done
  curl -sS "${API_ENDPOINT}" "${data[@]}"
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

echo "# automatisch generierte Konfiguration (KAS API)" >"${OUTPUT_FILE}" || exit 1

ftp_json=$(kas_api_request get_accounts "type=ftp")
db_json=$(kas_api_request get_databases)

mapfile -t ftp_logins < <(echo "${ftp_json}" | parse_json - "login")
mapfile -t ftp_dirs < <(echo "${ftp_json}" | parse_json - "dir")

if [ "${#ftp_logins[@]}" -ne "${#ftp_dirs[@]}" ]; then
  echo "Anzahl der FTP-Logins unterscheidet sich von der Anzahl der Verzeichnisse." >&2
  exit 1
fi

for i in "${!ftp_logins[@]}"; do
  login="${ftp_logins[$i]}"
  dir="${ftp_dirs[$i]#/www/htdocs/}"
  echo "mirror ${login} ${dir}" >>"${OUTPUT_FILE}"

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
  echo "database_backup ssh-${login} ${login} ${name} ${password}" >>"${OUTPUT_FILE}"
done

echo "Konfiguration nach ${OUTPUT_FILE} geschrieben." >&2
