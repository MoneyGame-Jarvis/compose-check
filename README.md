# compose-check

Find the settings in a `docker-compose.yml` that turn a hobby stack into
an incident.

```bash
python3 compose_check.py docker-compose.yml
```

```
compose-check: 1 file(s), 3 service(s), 9 finding(s)
[CRITICAL] web: mounts the Docker socket, which is root on the host
           -> remove it, or use a socket proxy with a read-only API subset
[CRITICAL] db: the environment variable DB_PASSWORD holds a literal secret
           -> move it to a secret and reference it with `secrets:`
[HIGH    ] web: adds the SYS_ADMIN capability, which is close to root
           -> drop the capability; almost nothing needs SYS_ADMIN or NET_ADMIN
...
```

No dependencies. No telemetry. Nothing leaves the machine — the file is
read, the findings are printed, and that is the whole program.

## Install

Copy `compose_check.py` and `miniyaml.py` into the same directory, or:

```bash
git clone https://github.com/MoneyGame-Jarvis/compose-check.git
cd compose-check
python3 compose_check.py docker-compose.yml
```

Python 3.9+. It uses PyYAML when it is installed, because PyYAML is the
reference implementation, and falls back to its own parser when it is
not. The fallback implements the subset of YAML a Compose file uses —
nested mappings and sequences, flow collections, quoted and block
scalars — and it is covered by the same tests.

## What it looks for

| Severity | Check | What it means |
|---|---|---|
| critical | `privileged` | the container is effectively root on the host |
| critical | `host-network` / `host-pid` | shares a host namespace |
| critical | `docker-sock` | the Docker socket is root on the host |
| critical | `secret-in-environment` | a literal password or key in `environment:` |
| high | `capabilities` | `SYS_ADMIN`, `NET_ADMIN` and friends |
| high | `host-mount` | `/etc`, `/root`, `/` and similar mounted in |
| high | `public-port` | published on `0.0.0.0` |
| medium | `unpinned-image` | `latest` or no tag at all |
| medium | `writable-rootfs` | the root filesystem can be written to |
| medium | `no-resource-limits` | one bug can take the host down |
| medium | `unbounded-logs` | `json-file` logs with no `max-size` |
| low | `no-healthcheck`, `runs-as-root`, `no-restart-policy`, `container-name` | worth fixing, not an incident |

## Options

```
-f, --file FILE     scan this file (repeatable)
--format text|json  human output, or JSON for a pipeline
--fail-on LEVEL     lowest severity that makes the exit code non-zero
                    (default: critical)
```

Exit code is `1` when something is found, `0` when the file is clean and
`2` when it cannot be parsed. That makes it usable as a CI gate:

```yaml
- name: compose-check
  run: python3 compose_check.py --fail-on high docker-compose.yml
```

## It is not a scanner

It reads one file and tells you what it can see. It does not know your
network, your firewall, or whether the secret in `environment:` is a
real secret. Treat the findings as a review checklist, not as a verdict.

## Why it exists

It is the free half of the
[Docker Compose Hardening Kit](https://yanisgangnant.gumroad.com/l/pvbiy)
— the same checklist that the paid kit turns into a full, annotated
reference with the reasoning, the fixes and the exceptions.

More checklists for people who run their own infrastructure:
[yanisgangnant.gumroad.com](https://yanisgangnant.gumroad.com/).

## Licence

MIT. See [LICENSE](LICENSE).
