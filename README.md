# Clean DNS rule sets for sing-box

This public repository contains only regenerated, domain-only rule sets for
DNS routing. It contains no sing-box configuration, proxy endpoint, account,
subscription, or credential.

The weekly GitHub Action fetches the upstream rule sources, removes all
address/IP predicates, recompiles with sing-box 1.14.0, and commits only the
seven resulting `.srs` files under `rules/`.
