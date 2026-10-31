# Local OWASP Juice Shop lab

This Compose setup runs Juice Shop on the local machine only:

- Host access is published on `127.0.0.1:8080`; it is not bound to LAN interfaces.
- The container is attached to an internal Docker network with no external
  routing.
- The app container is intentionally vulnerable. Keep this lab local and
  temporary; do not expose it through a proxy, tunnel, or router.
- The image tag is `latest`, so it is mutable. Record the resolved image digest
  alongside any benchmark or ground-truth results.

## Requirements

- Docker Desktop with Docker Compose enabled.
- CART's Python environment installed from the repository root.

## Start and verify the lab

From the repository root:

```powershell
docker compose -f labs/juice-shop/compose.yaml up -d
docker compose -f labs/juice-shop/compose.yaml ps
Invoke-WebRequest http://127.0.0.1:8080/ -UseBasicParsing
```

The HTTP check should return a successful response. If port 8080 is already in
use, stop the lab, change the host side of the `ports` mapping, and ensure the
new port is in CART's supported web-port list before testing.

Record which image was used:

```powershell
docker image inspect bkimminich/juice-shop:latest --format '{{.Id}}'
```

## Run CART against this instance

Use a separate database and report directory so the lab run does not mix with
other local CART data. The only selected address is the loopback host:

```powershell
.\.venv\Scripts\python.exe -m cart.cli --db .\cart-juice-shop.db select --prefix 127.0.0.1/32
.\.venv\Scripts\python.exe -m cart.cli --db .\cart-juice-shop.db run --tier breach --timeout 180 --report-dir .\reports\juice-shop
.\.venv\Scripts\python.exe -m cart.cli --db .\cart-juice-shop.db status
```

`127.0.0.1/32` constrains the network worker to one IPv4 address. The local
port mapping is 8080, which CART recognizes as an HTTP service; the web worker
uses the recorded service port and gates its requests against the locked
loopback scope. Do not substitute a public address, broad LAN prefix, or
organiser target without explicit authorization.

## Stop and clean up

```powershell
docker compose -f labs/juice-shop/compose.yaml down
```

The `down` command removes the lab container and network; no application data
volume is configured.

## Validation boundary

This lab makes local smoke testing possible; it does not itself establish
accuracy or a benchmark result. Before marking controlled validation complete,
record the image digest, CART commit, locked scope version, expected test
observations, run duration, audit-log results, and report. Verify that every
recorded network destination is loopback and that an out-of-scope test
destination is denied by unit tests rather than by probing a real external
system.
