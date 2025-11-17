#!/bin/bash

set -euo pipefail

# Konfigurationsvariable für Zielpfad
BACKUP_PATH=${BACKUP_PATH:-"/srv/backup"}
HOST=${HOST:-"w018d9ee.kasserver.com"}
CONFIG_FILE=${KAS_CONFIG_FILE:-"/etc/backup_kas.conf"}
GENERATED_CONFIG=${GENERATED_CONFIG:-"/tmp/kas_backup_api.sh"}
LOG_FILE=${LOG_FILE:-"/var/log/kas-backup.log"}
ENABLE_KAS_API_BACKUP=${ENABLE_KAS_API_BACKUP:-0}
export date=$(date "+%Y-%m-%d")

function mkdir_cd {
  echo -e "#####################################################################\n# mkdir_cd $1 \n#####################################################################"
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
  echo -e "#####################################################################\n# mirror $1 \n#####################################################################"
  rsync -av --delete -e "ssh -i /root/.ssh/id_rsa  -o StrictHostKeyChecking=no" "ssh-$1@${HOST}:/www/htdocs/${2}" . 2>&1 | tee -a "${LOG_FILE}"
  echo "warte 60 sec"
  sleep 60
}

function load_config {
  local config_path=$1
  if [ -f "${config_path}" ]; then
    # shellcheck source=/dev/null
    . "${config_path}"
  else
    echo "Konfigurationsdatei ${config_path} wurde nicht gefunden." >&2
    exit 1
  fi
}

echo -e ":::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::\n$(date)\n::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::" >>"${LOG_FILE}"

mkdir_cd kas/

mkdir_cd db/

if [ "${ENABLE_KAS_API_BACKUP}" -eq 1 ]; then
  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  if "${script_dir}/kas_api_generate_config.sh" "${GENERATED_CONFIG}"; then
    CONFIG_FILE="${GENERATED_CONFIG}"
  else
    echo "Generierung der KAS-API-Konfiguration fehlgeschlagen. Verwende statische Konfiguration." >&2
  fi
fi

load_config "${CONFIG_FILE}"
