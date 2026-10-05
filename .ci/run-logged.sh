#!/bin/bash
# run-logged.sh
#   Run a command with its output redirected to a log file instead of the job
#   log, so verbose builds do not exceed GitLab's job log size limit before
#   the failure is reached. On failure, print the error lines and the tail of
#   the log so the cause is visible in the job log.
# Inputs:
#   $1 - log name; output goes to $CI_LOG_DIR/<name>.log
#   $@ - (remaining) the command to run
#   CI_LOG_DIR   - log directory (default: $CI_PROJECT_DIR/ci-logs)
#   CI_LOG_TAIL  - lines of log tail to print on failure (default: 200)
# Outputs:
#   The command's exit status; the full log is left in $CI_LOG_DIR.
set -uo pipefail

log_name="$1"
shift
log_dir="${CI_LOG_DIR:-${CI_PROJECT_DIR:-$(pwd)}/ci-logs}"
tail_lines="${CI_LOG_TAIL:-200}"
mkdir -p "$log_dir"
log_file="$log_dir/$log_name.log"

echo "running: $* (output in $log_file)"
"$@" > "$log_file" 2>&1
status=$?

if [[ $status -ne 0 ]]; then
  echo "===== '$log_name' failed with exit status $status ====="
  # unittest prints one "FAIL:"/"ERROR:" header per failing (sub)test.
  echo "----- failing tests -----"
  grep -E '^([0-9]+: )?(FAIL|ERROR): ' "$log_file" | sort -u
  echo "----- error lines (first 100) -----"
  grep -n -E -i '(error|failed|fatal|undefined reference)' "$log_file" | head -n 100
  echo "----- last $tail_lines lines -----"
  tail -n "$tail_lines" "$log_file"
fi
exit $status
