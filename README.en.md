# offline-ubuntu-healthcheck

An offline security health check for Ubuntu hosts.

A read-only script collects the package list and a few system facts on each host. It installs nothing and needs no network access. The bundle is analysed on another machine against **Canonical's official OVAL data**, and the tool writes a report (in Traditional Chinese) that marks which issues an Ubuntu Pro subscription would resolve.

> This is not an official Canonical tool. It is not affiliated with or endorsed by Canonical. Ubuntu is a trademark of Canonical Ltd.

## How it works

1. **Update data** on an internet-connected machine: `python3 update-data.py` downloads `oci.com.ubuntu.<codename>.usn.oval.xml.bz2` from `security-metadata.canonical.com` and records SHA-256 hashes, so the files can be verified after transfer (`--verify`).
2. **Collect** on each host: `bash collect.sh --tag H01` (no root needed; with `sudo` it also checks the SSH config, ufw and empty passwords).
3. **Analyse** offline: `python3 analyze.py hc-*.tar.gz`. Matching uses OpenSCAP (`oscap`) when available, otherwise a built-in evaluator of the same OVAL definitions. Use `--engine both` to compare the two.

The tool decides whether a fix needs Ubuntu Pro from the pocket that the official OVAL criteria name (`esm-infra`, `esm-apps`, `esm-infra-legacy`). It does not guess from version strings.

Supported releases: 14.04, 16.04, 18.04, 20.04, 22.04, 24.04 and 26.04 LTS.

## Relation to sec-cvescan

The approach (export a package manifest, scan it elsewhere offline) follows Canonical's [sec-cvescan](https://github.com/canonical/sec-cvescan). That project is deprecated and its data feed is no longer updated. This tool uses the maintained official OVAL feed instead. No sec-cvescan code is used.

## Customising

Classification, severities, advice texts, lifecycle dates and thresholds live in `rules/default-rules.json`. To change them, write an override file and pass it with `--rules` (see `docs/custom-rules.md`). `findings.json` can be handed to an AI assistant together with `ai-skill/SKILL.md`.

## License

The code is licensed under the Apache License 2.0. The OVAL data is © Canonical Ltd.; the raw files are not redistributed here (the sample report quotes advisory titles and CVE IDs from it).
