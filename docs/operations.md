# Operations

## Safe execution

Run `cache-doctor cargo` against the local Cargo home or
`cache-doctor inspect PATH --format json` against a fixture or cache path. The
tool performs filesystem reads only. It does not invoke Cargo, access a
registry, install packages, modify files, or read credential values.

Use `--offline` to mark the operator's intended context in the report. The
flag does not change the scanner's already network-free behavior.

## Reports and retention

JSON is the default output and text output is available for a concise
explanation. Reports contain the selected root, local paths, findings, and
error text. Store them under the local retention and access policy.

## Troubleshooting

- `complete: false` means a filesystem read or bound error prevented a fully
  completed scan. Read the `errors` array.
- `artifact_missing` means a lockfile package had no matching cached artifact.
- `missing_transitive_metadata` means a lockfile package had no recognized
  index record.
- `checksum_mismatch` means the bounded artifact digest differs from index
  metadata.
- `authentication_assumption` means source replacement was detected without a
  credential file presence signal. The scanner did not validate credentials.
- `stale_index` is a timestamp-based clue, not proof that Cargo will reject
  the cache.

## Recovery

The scanner does not change the cache, so no scanner rollback is required. If
another process is populating or pruning the cache, rerun after that process
has stopped. Use Cargo's own offline diagnostics to decide what repair or
fetch action is appropriate.
