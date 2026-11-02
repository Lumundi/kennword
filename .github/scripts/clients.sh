#!/usr/bin/env bash
#
# Starts a server with an empty SQLite database and the web vault behind an
# HTTPS proxy, and runs the tests of tests/Clients against it, which drive the
# official Bitwarden clients: this implementation by default, Vaultwarden when
# its binary is given. A second server of the same kind logs in with SSO.
#
# Usage: clients.sh [--vaultwarden <binary>] [--serve] [playwright arguments...]
# --serve starts the servers and keeps them running, for `npx playwright test`
# by hand (with the environment it prints).
#
# Needs the web vault in WEB_VAULT_FOLDER (php artisan kennword:web-vault) and
# `npm ci` and `npx playwright install chromium` in tests/Clients. PHP is `php`
# unless PHP names another; it also runs the SMTP sink, which keeps the mail the
# servers send for the tests, and the OpenID provider. Ports 8100 to 8105, 8443
# and 8444 must be free, and 8065, where the CLI waits for the end of its SSO login.

set -euo pipefail

binary=
serve=false
while [[ $# -gt 0 ]]; do
    case "$1" in
        --vaultwarden) binary="$(realpath "$2")"; shift 2 ;;
        --serve) serve=true; shift ;;
        *) break ;;
    esac
done
php="${PHP:-php}"
root="$(pwd)"
work="$(mktemp -d)"
mkdir -p "${work}/data"

for port in 8065 8100 8101 8102 8103 8104 8105 8443 8444; do
    if (echo > "/dev/tcp/127.0.0.1/${port}") 2> /dev/null; then
        echo "::error::Port ${port} is in use."
        exit 1
    fi
done
pids=()
stop() {
    for pid in ${pids[@]+"${pids[@]}"}; do
        # PHP's server workers outlive their parent unless they are stopped first.
        pkill -P "${pid}" 2> /dev/null || true
        kill "${pid}" 2> /dev/null || true
    done
}
trap stop EXIT

# The clients accept nothing but HTTPS: a certificate for 127.0.0.1 from an authority of its own,
# which the CLI trusts through NODE_EXTRA_CA_CERTS.
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj '/CN=Clients CA' -addext 'basicConstraints=critical,CA:TRUE' \
    -addext 'keyUsage=critical,keyCertSign' -keyout "${work}/ca.key" -out "${work}/ca.pem" 2> /dev/null
openssl req -newkey rsa:2048 -nodes -subj '/CN=127.0.0.1' -keyout "${work}/server.key" -out "${work}/server.csr" 2> /dev/null
printf 'subjectAltName=IP:127.0.0.1,DNS:localhost\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n' \
    > "${work}/server.ext"
openssl x509 -req -in "${work}/server.csr" -CA "${work}/ca.pem" -CAkey "${work}/ca.key" -CAcreateserial -days 2 \
    -extfile "${work}/server.ext" -out "${work}/server.pem" 2> /dev/null

url=https://127.0.0.1:8443
export DATA_FOLDER="${work}/data" DOMAIN="${url}" WEB_VAULT_FOLDER="$(realpath "${WEB_VAULT_FOLDER:-web-vault}")/"
if [[ ! -f "${WEB_VAULT_FOLDER}index.html" ]]; then
    echo "::error::No web vault in ${WEB_VAULT_FOLDER}; install it with php artisan kennword:web-vault."
    exit 1
fi

# Invitations reach their accounts by mail, as they would in production: the server sends it to a sink
# that keeps every message in a folder the tests read.
"${php}" .github/scripts/smtp-sink.php 8102 "${work}/mail" > "${work}/sink.log" 2>&1 &
pids+=($!)
export SMTP_HOST=127.0.0.1 SMTP_PORT=8102 SMTP_SECURITY=off SMTP_FROM=vaultwarden@example.com SMTP_TIMEOUT=5
# Every client connects from 127.0.0.1, where people would each have an address of their own: the login
# limit allows the default burst of 10 for each of the tests' accounts. The other limits are the defaults.
export LOGIN_RATELIMIT_MAX_BURST="${LOGIN_RATELIMIT_MAX_BURST:-30}"

# Starts a server on a backend port with the environment given: Vaultwarden, or ours with its
# notifications daemon on the next port; and the HTTPS proxy in front of it.
serve() {
    local name="$1" port="$2" proxy="$3" hub=
    shift 3
    if [[ -n "${binary}" ]]; then
        env "$@" ROCKET_ADDRESS=127.0.0.1 ROCKET_PORT="${port}" "${binary}" > "${work}/${name}.log" 2>&1 &
        pids+=($!)
    else
        env "$@" "${php}" artisan kennword:migrate --no-ansi > /dev/null
        # php -S rather than artisan serve, which drops most environment variables. Laravel's router
        # script expects to run in the public folder. The web vault loads many files at once.
        (cd public && exec env "$@" PHP_CLI_SERVER_WORKERS=4 CACHE_PATH="${work}/${name}-cache" "${php}" -d upload_max_filesize=525M \
            -d post_max_size=0 -S "127.0.0.1:${port}" ../vendor/laravel/framework/src/Illuminate/Foundation/resources/server.php) \
            > "${work}/${name}.log" 2>&1 &
        pids+=($!)
        hub="http://127.0.0.1:$((port + 1))"
        env "$@" "${php}" artisan kennword:notifications --listen="${hub#http://}" --no-ansi > "${work}/${name}-notifications.log" 2>&1 &
        pids+=($!)
    fi
    node tests/Clients/proxy.mjs "${proxy}" "${work}/server.pem" "${work}/server.key" "http://127.0.0.1:${port}" ${hub:+"${hub}"} \
        > "${work}/${name}-proxy.log" 2>&1 &
    pids+=($!)
}
serve server 8100 8443

# The second server logs in with SSO (sso.spec.ts), which changes the web vault's login page, at the fake
# OpenID provider of fake-services.php. The provider logs in whoever the tests name on its authorization URL.
sso_url=https://127.0.0.1:8444
SSO_CLIENT_SECRET=clients-sso-secret "${php}" .github/scripts/fake-services.php 8103 "${work}/server.pem" "${work}/server.key" \
    "${work}/services" > "${work}/services.log" 2>&1 &
pids+=($!)
mkdir -p "${work}/sso-data"
serve sso 8104 8444 DATA_FOLDER="${work}/sso-data" DOMAIN="${sso_url}" SSO_ENABLED=true SSO_AUTHORITY=https://127.0.0.1:8103/oidc \
    SSO_CLIENT_ID=vaultwarden SSO_CLIENT_SECRET=clients-sso-secret SSO_SCOPES="email profile offline_access" SSL_CERT_FILE="${work}/ca.pem"

for attempt in $(seq 60); do
    curl -fsS --cacert "${work}/ca.pem" "${url}/alive" > /dev/null 2>&1 && curl -fsS --cacert "${work}/ca.pem" "${sso_url}/alive" > /dev/null 2>&1 && break
    if [[ "${attempt}" == 60 ]]; then
        tail -30 "${work}"/*.log
        echo "::error::${url} or ${sso_url} did not answer."
        exit 1
    fi
    sleep 1
done

export VW_CLIENTS_URL="${url}" VW_CLIENTS_SSO_URL="${sso_url}" VW_CLIENTS_MAIL="${work}/mail" NODE_EXTRA_CA_CERTS="${work}/ca.pem"
# Where the tests expect Vaultwarden to differ (known upstream bugs that we fix).
export VW_CLIENTS_SERVER="${binary:+vaultwarden}"
if [[ "${serve}" == true ]]; then
    echo "Serving ${url} and ${sso_url} (logs in ${work}). In tests/Clients, run:"
    echo "VW_CLIENTS_URL=${url} VW_CLIENTS_SSO_URL=${sso_url} VW_CLIENTS_MAIL=${work}/mail NODE_EXTRA_CA_CERTS=${work}/ca.pem VW_CLIENTS_SERVER=${VW_CLIENTS_SERVER} npx playwright test"
    wait
fi

status=0
(cd "${root}/tests/Clients" && npx playwright test "$@") || status=$?
if [[ "${status}" != 0 ]]; then
    for log in "${work}"/*.log; do
        echo "--- ${log}"
        tail -50 "${log}"
    done
fi
exit "${status}"
