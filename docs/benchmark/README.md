# Benchmark results

Raw evaluation data and the tables generated from it.

## Layout

```
data/<tag>/<workload>.json     per workload results for one run
data/<tag>/environment.json    kernel, cores, load, runtime hash, git commit
data/<tag>/profiles/*.json     the generated seccomp profiles that run used
data/<tag>/captures/*.json     the syscall captures the profiles came from
data/<tag>/logs/               container output per iteration
data/<tag>/tables/*.csv        the rendered tables as data
results-<tag>.md               the rendered tables as prose
```

Raw JSON, generated profiles and tables are committed: they are the evidence.
Container logs are regenerated rather than kept.

## Reproducing

```bash
sudo scripts/reproduce.sh --quick          # a few minutes, validates the pipeline
sudo scripts/reproduce.sh --tag $(date +%F) # the full corpus
```

Expect the full run to take a while: five workloads, four arms, 30 measured
iterations plus warmups, and learn mode traps on every syscall.

## Reading the numbers

`docs/research/methodology.md` defines every column. Three things to keep in
mind before quoting anything:

- The Docker baseline is 296 syscalls on x86_64, not the 441 names its profile
  lists. Rules gated on capabilities a default container lacks do not apply.
- A CVE counts as blocked only when every attack path is cut. Entries in
  `data/cve-syscall-map.json` marked below high confidence need checking against
  NVD first.
- Learn-mode timings are a one-off offline cost and are not comparable with the
  other arms.
