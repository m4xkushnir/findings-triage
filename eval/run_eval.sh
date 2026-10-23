#!/usr/bin/env bash
# Reproduce the README's evaluation.
#
#   uv run bash eval/run_eval.sh /path/to/eval-dir               # scan + report (needs scanners)
#   SKIP_SCAN=1 uv run bash eval/run_eval.sh /path/to/eval-dir    # re-ingest saved reports only
#
# The eval dir is created with clones at the commits used in the README. Trivy's default DB
# mirror is overridable with TRIVY_DB / TRIVY_CHECKS (the README run used ghcr.io).
set -euo pipefail

EVAL=${1:?usage: run_eval.sh EVAL_DIR}
HERE=$(cd "$(dirname "$0")" && pwd)
TRIAGE=${TRIAGE:-triage}
AS_OF=2026-10-23
TRIVY_DB=${TRIVY_DB:-ghcr.io/aquasecurity/trivy-db:2}
TRIVY_CHECKS=${TRIVY_CHECKS:-ghcr.io/aquasecurity/trivy-checks:2}

repo() {  # name -> "url commit" (bash 3 compatible: no associative arrays)
  case $1 in
    juice-shop) echo "https://github.com/juice-shop/juice-shop.git 717f5efa8" ;;
    flask) echo "https://github.com/pallets/flask.git d086db856" ;;
    gin) echo "https://github.com/gin-gonic/gin.git 0f09c3a9b" ;;
  esac
}
HISTORY_OLD=64bda9aa8
HISTORY_NEW=717f5efa8

mkdir -p "$EVAL" && cd "$EVAL"

scan() {  # scan ROOT OUT_DIR
  if [[ -n "${SKIP_SCAN:-}" ]]; then
    "$TRIAGE" scan "$1" -o "$2/run.json" \
      -i "$2/raw/semgrep.sarif" -i "$2/raw/trivy.sarif" -i "$2/raw/gitleaks.json"
  else
    "$TRIAGE" scan "$1" -o "$2/run.json" \
      --trivy-db-repository "$TRIVY_DB" --trivy-checks-repository "$TRIVY_CHECKS"
  fi
}

for name in juice-shop flask gin; do
  read -r url sha <<<"$(repo "$name")"
  if [[ ! -d $name ]]; then git clone --quiet "$url" "$name"; fi
  git -C "$name" checkout --quiet --detach "$sha"
done

# Juice Shop does not commit a lockfile. Resolve one without running install scripts.
if [[ ! -f juice-shop/package-lock.json ]]; then
  (cd juice-shop && npm install --package-lock-only --ignore-scripts --no-audit --no-fund --loglevel=error)
  (cd juice-shop/frontend && npm install --package-lock-only --ignore-scripts --no-audit --no-fund --loglevel=error)
fi

echo "== funnel"
for name in juice-shop flask gin; do
  scan "$name" "out/$name"
  "$TRIAGE" report "out/$name/run.json" -o "out/$name/report-off" --enrich off --as-of $AS_OF --fail-on never
  "$TRIAGE" report "out/$name/run.json" -o "out/$name/report" --enrich heuristic --as-of $AS_OF --fail-on never
  if [[ -f "$HERE/suppressions/$name.yaml" ]]; then
    "$TRIAGE" report "out/$name/run.json" -o "out/$name/report-suppressed" --enrich heuristic \
      --as-of $AS_OF --fail-on never --suppressions "$HERE/suppressions/$name.yaml"
  fi
done

echo "== audit log and replay (Juice Shop)"
rm -f out/juice-shop/audit.jsonl
"$TRIAGE" report out/juice-shop/run.json -o out/juice-shop/report-suppressed --enrich heuristic \
  --as-of $AS_OF --fail-on never --suppressions "$HERE/suppressions/juice-shop.yaml" \
  --audit-log out/juice-shop/audit.jsonl
"$TRIAGE" verify-log out/juice-shop/audit.jsonl
"$TRIAGE" replay --audit-log out/juice-shop/audit.jsonl

echo "== stability: real history"
for side in old new; do
  sha=$([[ $side == old ]] && echo $HISTORY_OLD || echo $HISTORY_NEW)
  if [[ ! -d wt/juice-$side ]]; then git -C juice-shop worktree add --quiet --detach "../wt/juice-$side" "$sha"; fi
  scan "wt/juice-$side" "out/history/juice-$side"
done
python3 "$HERE/stability.py" juice-shop $HISTORY_OLD $HISTORY_NEW \
  out/history/juice-old/run.json out/history/juice-new/run.json | tee out/history/stability.json

echo "== stability: synthetic refactor"
for name in juice-shop flask gin; do
  if [[ -z "${SKIP_SCAN:-}" ]]; then
    rm -rf "synth/$name-base"
    mkdir -p synth && rsync -a --exclude .git --exclude node_modules "$name/" "synth/$name-base/"
    python3 "$HERE/synthetic_refactor.py" "synth/$name-base" "synth/$name-refactor"
  fi
  scan "synth/$name-base" "out/synth/$name-base"
  scan "synth/$name-refactor" "out/synth/$name-refactor"
  echo "$name: $("$TRIAGE" diff "out/synth/$name-base/run.json" "out/synth/$name-refactor/run.json" --no-show)"
done

echo "== LLM prompt budget (no API calls)"
for name in juice-shop flask gin; do
  echo "$name"; python3 "$HERE/prompt_budget.py" "out/$name/run.json"
done
