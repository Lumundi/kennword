#!/usr/bin/env bash
#
# Moves an installation from Vaultwarden to this implementation and back
# (tests/Migration/MigrationTest), on each database type given:
#
#   1. Vaultwarden starts on a new database and data folder; the test fills
#      them through its API.
#   2. Vaultwarden stops. vaultwarden:check finds nothing that needs attention,
#      and vaultwarden:migrate runs, as an operator would before switching.
#   3. We serve the same database and data folder on the same port; the test
#      reads everything back and changes it.
#   4. Vaultwarden starts on what we left; the test reads our changes.
#
# Usage: migration.sh <vaultwarden binary> <sqlite|mysql|pgsql>...
# Ports 8010 and 2510 (SMTP sink) must be free. MySQL and PostgreSQL must listen on
# 127.0.0.1 with user root and no password; the script creates the database
# migration_test there and fails if it exists. It is meant for the throwaway CI services.

set -euo pipefail

binary="$(realpath "$1")"
shift
work="${VW_MIGRATION_WORK:-$(mktemp -d)}"
port=8010
url="http://127.0.0.1:${port}"
failed=0

pids=()
trap 'kill "${pids[@]}" 2> /dev/null || true' EXIT

fail() {
    echo "::error::$1"
    failed=1
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

# Waits until the server answers; shows its log if it does not.
wait_for() {
    local log="$1"
    for _ in $(seq 60); do
        curl -fsS "${url}/alive" > /dev/null 2>&1 && return 0
        sleep 1
    done
    cat "${log}"
    return 1
}

stop() {
    kill "$1" 2> /dev/null || true
    wait "$1" 2> /dev/null || true
}

php .github/scripts/smtp-sink.php 2510 "${work}/inbox" > "${work}/sink.log" 2>&1 &
pids+=($!)

# What both servers run with: the admin panel, groups and events on, mail to the sink, no web
# vault, and Vaultwarden's login limits raised, since every phase logs in many times.
export ADMIN_TOKEN=migration-admin-token VW_MIGRATION_ADMIN_TOKEN=migration-admin-token \
    WEB_VAULT_ENABLED=false ORG_GROUPS_ENABLED=true ORG_EVENTS_ENABLED=true \
    SMTP_HOST=127.0.0.1 SMTP_PORT=2510 SMTP_SECURITY=off SMTP_FROM=vaultwarden@example.com SMTP_TIMEOUT=5 \
    LOGIN_RATELIMIT_MAX_BURST=10000 UNAUTHENTICATED_RATELIMIT_MAX_BURST=10000

for connection in "$@"; do
    case "${connection}" in
        sqlite) database_url="" ;;
        mysql) database_url="mysql://root@127.0.0.1:3306/migration_test" ;;
        pgsql) database_url="postgresql://root@127.0.0.1:5432/migration_test" ;;
        *)
            echo "Unknown database type ${connection}." >&2
            exit 2
            ;;
    esac
    echo "::group::${connection}"

    export DATA_FOLDER="${work}/${connection}/data"
    state="${work}/${connection}/state"
    mkdir -p "${DATA_FOLDER}" "${state}"
    if [[ -n "${database_url}" ]]; then
        export DATABASE_URL="${database_url}"
    else
        unset DATABASE_URL
    fi
    create_database "${connection}" migration_test

    # phase <name>: runs that phase of the test against the server on the port.
    phase() {
        VW_MIGRATION_URL="${url}" VW_MIGRATION_PHASE="$1" VW_MIGRATION_STATE="${state}" VW_MIGRATION_MAIL_DIR="${work}/inbox" \
            vendor/bin/phpunit --testsuite Migration --do-not-cache-result
    }
    vaultwarden() {
        ROCKET_PORT="${port}" "${binary}" > "${work}/${connection}/vaultwarden-$1.log" 2>&1 &
        pid=$!
        pids+=("${pid}")
        wait_for "${work}/${connection}/vaultwarden-$1.log"
    }
    # php -S rather than artisan serve, which drops most environment variables.
    kennword() {
        (cd public && CACHE_PATH="${work}/${connection}/cache" exec php -d upload_max_filesize=525M -d post_max_size=0 -S "127.0.0.1:${port}" \
            ../vendor/laravel/framework/src/Illuminate/Foundation/resources/server.php) > "${work}/${connection}/kennword.log" 2>&1 &
        pid=$!
        pids+=("${pid}")
        wait_for "${work}/${connection}/kennword.log"
    }

    # Each step needs the ones before; the first that fails ends the run on this database.
    move() {
        vaultwarden fill || { fail "${connection}: Vaultwarden did not start."; return; }
        phase fill || { fail "${connection}: Vaultwarden could not fill the installation."; return; }
        stop "${pid}"

        php artisan vaultwarden:check --no-ansi || { fail "${connection}: vaultwarden:check found problems in Vaultwarden's installation."; return; }
        php artisan vaultwarden:migrate --no-ansi || { fail "${connection}: vaultwarden:migrate failed on Vaultwarden's installation."; return; }

        kennword || { fail "${connection}: Kennword did not start."; return; }
        phase move || { fail "${connection}: the installation did not move over intact."; return; }
        stop "${pid}"

        php artisan vaultwarden:check --no-ansi || { fail "${connection}: vaultwarden:check found problems in what Kennword left."; return; }
        vaultwarden back || { fail "${connection}: Vaultwarden did not start on what Kennword left."; return; }
        phase back || { fail "${connection}: Vaultwarden did not read what Kennword left."; return; }
        stop "${pid}"
    }
    pid=""
    move
    if [[ -n "${pid}" ]]; then stop "${pid}"; fi

    if [[ "${failed}" != 0 ]]; then
        for log in "${work}/${connection}"/*.log; do
            echo "--- ${log}"
            tail -40 "${log}"
        done
    fi
    echo "::endgroup::"
done

exit "${failed}"
