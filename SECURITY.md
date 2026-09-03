# Security policy

## Supported versions

The latest `0.1.x` release receives security fixes while the project remains
in the 0.1 series.

## Reporting a vulnerability

Do not put credentials, private cache paths, or private reproducer data in a
public issue. Use GitHub's private vulnerability reporting for this repository
when available. If it is unavailable, open an issue with only a short,
non-sensitive description and request a private contact path.

cache-doctor is read-only and does not upload cache data. Reports can contain
operator-supplied paths and error text, so store them with suitable
permissions. The scanner records credential file presence but never reads
credential values.
