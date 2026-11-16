# offline-ubuntu-healthcheck

An offline security health check for Ubuntu hosts.

It tells you whether each host's release is still maintained, which security fixes are missing, and which of those gaps an Ubuntu Pro subscription would close. Matching uses **Canonical's official OVAL data**. Nothing is installed on the hosts being checked. Reports are written in Traditional Chinese.

> This is not an official Canonical tool. It is not affiliated with or endorsed by Canonical. Ubuntu is a trademark of Canonical Ltd.

## One command

```bash
git clone https://github.com/ikusupuroa/offline-ubuntu-healthcheck.git
cd offline-ubuntu-healthcheck
./hc update                 # download Canonical OVAL data (the only step that needs internet)
```

| Situation | Command |
|---|---|
| This machine can SSH to the hosts | `./hc scan hosts.txt` (one line per host: `TAG user@host [ssh options]`) |
| Host owners run the collector themselves | on the host: `bash collect.sh --tag H01`; then `./hc report hc-H01-*.tar.gz` |
| Check this machine only | `./hc local` |

`./hc scan` pipes the collector over SSH and streams the result back, so nothing is left on the host. Add `--sudo` to also check the SSH config, ufw and empty passwords (needs passwordless sudo; otherwise it falls back to a normal user).

The run ends with a summary on screen. Open `report.html` in a browser for the full report.

## How it decides "needs Ubuntu Pro"

It reads the fix pocket named in the official OVAL criteria (`esm-infra`, `esm-apps`, `esm-infra-legacy`). It does not guess from version strings. Matching uses OpenSCAP (`oscap`) when available, otherwise a built-in evaluator of the same definitions. `--engine both` runs both and lists any differences.

Before collecting, the tool checks the OVAL data and offers to update anything older than 7 days; before analysing, it shows the date of the data used for each release. `--data PATH` points to data you manage yourself, and `./hc update --verify` checks files after moving them into an air-gapped network.

## More

- `tests/lxd-quicktest.sh`: one-command test across Ubuntu releases in LXD VMs
- `rules/default-rules.json`: categories, advice texts and thresholds; override with `--rules`
- `ai-skill/SKILL.md`: instructions for analysing `findings.json` with an AI assistant

## Relation to sec-cvescan

The approach (export a package manifest, scan it elsewhere offline) follows Canonical's [sec-cvescan](https://github.com/canonical/sec-cvescan). That project is deprecated and its data feed is no longer updated. This tool uses the maintained official OVAL feed instead. No sec-cvescan code is used.

## License

The code is licensed under the Apache License 2.0. The OVAL data is © Canonical Ltd. and licensed under CC BY-SA 4.0. The raw files are not redistributed here; the sample report quotes advisory titles and CVE IDs from them.
