#!/usr/bin/env bash
#
# Compares the databases Vaultwarden creates with the ones our migrator creates.
# For each database type given:
#
#   1. Vaultwarden creates a database. Its snapshot (php artisan parity:schema) is
#      written to parity/schema/<dialect>.json; the caller compares that with the
#      committed snapshot.
#   2. Our migrator finds nothing to do in Vaultwarden's database.
#   3. Our migrator creates a database with exactly that snapshot.
#   4. Vaultwarden starts on our database and leaves its snapshot unchanged.
#
# Usage: database-parity.sh <vaultwarden binary> <sqlite|mysql|pgsql>...
# MySQL and PostgreSQL must listen on 127.0.0.1 with user root and no password;
# the script creates the databases parity_vaultwarden and parity_kennword
# there and fails if they exist. It is meant for the throwaway CI services.

set -euo pipefail

binary="$(realpath "$1")"
shift
work="$(mktemp -d)"
failed=0

fail() {
    echo "::error::$1"
    failed=1
}

# php artisan with the given connection pointed at a database (a file for SQLite).
artisan() {
    local connection="$1" database="$2" port=""
    shift 2
    case "${connection}" in
        mysql) port=3306 ;;
        pgsql) port=5432 ;;
    esac
    DB_CONNECTION="${connection}" DB_HOST=127.0.0.1 DB_PORT="${port}" DB_USERNAME=root DB_PASSWORD= \
        DB_DATABASE="${database}" php artisan "$@" --database="${connection}" --no-ansi
}

# Creates a new database; fails rather than touch one that already exists.
create_database() {
    local connection="$1" database="$2" dsn
    case "${connection}" in
        mysql) dsn="mysql:host=127.0.0.1;port=3306" ;;
        pgsql) dsn="pgsql:host=127.0.0.1;port=5432;dbname=postgres" ;;
        *) return 0 ;;
    esac
    php -r '$pdo = new PDO($argv[1], "root", "", [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
        $pdo->exec("CREATE DATABASE {$argv[2]}");' "${dsn}" "${database}"
}

# Start Vaultwarden until it answers, then stop it. Without a URL it uses the
# SQLite database in its data folder.
run_vaultwarden() {
    local data="$1" url="$2" pid
    mkdir -p "${data}"
    (
        if [[ -n "${url}" ]]; then export DATABASE_URL="${url}"; fi
        exec env DATA_FOLDER="${data}" WEB_VAULT_ENABLED=false ROCKET_PORT=8000 "${binary}"
    ) > "${data}/vaultwarden.log" 2>&1 &
    pid=$!

    for _ in $(seq 60); do
        if curl -fsS http://127.0.0.1:8000/alive > /dev/null 2>&1; then
            kill "${pid}"
            wait "${pid}" 2> /dev/null || true
            return 0
        fi
        sleep 1
    done

    kill "${pid}" 2> /dev/null || true
    cat "${data}/vaultwarden.log"
    return 1
}

for connection in "$@"; do
    case "${connection}" in
        sqlite)
            dialect=sqlite
            theirs="${work}/theirs-sqlite/db.sqlite3" theirs_url=""
            ours="${work}/ours-sqlite/db.sqlite3" ours_url=""
            ;;
        mysql)
            dialect=mysql
            theirs=parity_vaultwarden theirs_url="mysql://root@127.0.0.1:3306/parity_vaultwarden"
            ours=parity_kennword ours_url="mysql://root@127.0.0.1:3306/parity_kennword"
            ;;
        pgsql)
            dialect=postgresql
            theirs=parity_vaultwarden theirs_url="postgresql://root@127.0.0.1:5432/parity_vaultwarden"
            ours=parity_kennword ours_url="postgresql://root@127.0.0.1:5432/parity_kennword"
            ;;
        *)
            echo "Unknown database type ${connection}." >&2
            exit 2
            ;;
    esac
    snapshot="parity/schema/${dialect}.json"

    echo "::group::${dialect}"

    create_database "${connection}" "${theirs}"
    if ! run_vaultwarden "${work}/theirs-${connection}" "${theirs_url}"; then
        fail "${dialect}: Vaultwarden did not start on a new database."
        echo "::endgroup::"
        continue
    fi
    artisan "${connection}" "${theirs}" parity:schema --output="${snapshot}"

    artisan "${connection}" "${theirs}" kennword:migrate > "${work}/migrate.log"
    if ! grep -q 'Nothing to migrate' "${work}/migrate.log"; then
        cat "${work}/migrate.log"
        fail "${dialect}: our migrator wanted to change the database Vaultwarden created."
    fi

    create_database "${connection}" "${ours}"
    artisan "${connection}" "${ours}" kennword:migrate > /dev/null
    artisan "${connection}" "${ours}" parity:schema --output="${work}/ours-${dialect}.json" > /dev/null
    if ! diff -u "${snapshot}" "${work}/ours-${dialect}.json"; then
        fail "${dialect}: our migrator creates a different schema than Vaultwarden."
    fi

    if ! run_vaultwarden "${work}/ours-${connection}" "${ours_url}"; then
        fail "${dialect}: Vaultwarden did not start on the database our migrator created."
    else
        artisan "${connection}" "${ours}" parity:schema --output="${work}/ours-after-${dialect}.json" > /dev/null
        if ! diff -u "${work}/ours-${dialect}.json" "${work}/ours-after-${dialect}.json"; then
            fail "${dialect}: Vaultwarden changed the database our migrator created."
        fi
    fi

    echo "::endgroup::"
done

exit "${failed}"
