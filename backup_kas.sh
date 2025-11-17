#!/bin/bash

# Konfigurationsvariable für Zielpfad
BACKUP_PATH="/srv/backup"
HOST="w018d9ee.kasserver.com"
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
  ssh -i "/root/.ssh/id_rsa" -o StrictHostKeyChecking=no "${1}@${HOST}" mysqldump "-u${2}" "-p${4}" "${3}" >"${backupfile}" 2>>/var/log/kas-backup.log
  ls -la "${backupfile}"
  tail -n 1 "${backupfile}"
  echo "warte 60 sec"
  sleep 60
}

function mirror {
  echo -e "#####################################################################\n# mirror $1 \n#####################################################################"
  rsync -av --delete -e "ssh -i /root/.ssh/id_rsa  -o StrictHostKeyChecking=no" "ssh-$1@${HOST}:/www/htdocs/${2}" . 2>&1 | tee -a /var/log/kas-backup.log
  echo "warte 60 sec"
  sleep 60
}

echo -e ":::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::\n$(date)\n:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::" >>/var/log/kas-backup.log

mkdir_cd kas/

mkdir_cd db/

. /etc/kas_backup.sh

