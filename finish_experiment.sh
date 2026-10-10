#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT="$HOME/secure-iot-ids"
LIVE="$PROJECT/live_cooja_ids.log"
STATE="$PROJECT/.finish_experiment_last_marker"
ARCHIVES="$PROJECT/experiment_archive/finished_runs"

scenario="${1:-}"

case "$scenario" in
  flood_no_ids)
    LOG="$PROJECT/flood_no_ids_log.txt"
    ;;
  flood_ids)
    LOG="$PROJECT/flood_ids_log.txt"
    ;;
  sinkhole_no_ids)
    LOG="$PROJECT/sinkhole_no_ids_log.txt"
    ;;
  sinkhole_ids)
    LOG="$PROJECT/sinkhole_fast_ids_final_log.txt"
    ;;
  *)
    echo "Usage: ./finish_experiment.sh {flood_no_ids|flood_ids|sinkhole_no_ids|sinkhole_ids}"
    exit 2
    ;;
esac

fail() {
  echo
  echo "NOT SAVED: $*"
  echo "Your existing canonical log has been preserved."
  exit 1
}

count_fixed() {
  local n
  n=$(grep -Fc -- "$1" "$2" || true)
  printf '%s' "${n:-0}"
}

[[ -f "$LIVE" ]] || fail "Cannot find $LIVE. Check that the Cooja logger is running."

marker=$(grep -nF "SCRIPT_LOGGER_STARTED" "$LIVE" | tail -n 1 | cut -d: -f1 || true)
[[ "$marker" =~ ^[0-9]+$ ]] || fail "No Cooja logger start marker found."

previous=$(cat "$STATE" 2>/dev/null || printf '0')
[[ "$previous" =~ ^[0-9]+$ ]] || previous=0

if (( marker <= previous )); then
  fail "No new Cooja logger session detected. Run the simulation first, then retry."
fi

TMP="$PROJECT/.$scenario.$$.tmp"
TRIM="$TMP.trim"
trap 'rm -f "$TMP" "$TRIM"' EXIT

# Extract the latest logger session only.
tail -n "+$marker" "$LIVE" > "$TMP"

if [[ "$scenario" == flood_no_ids || "$scenario" == flood_ids ]]; then

  grep -qF "FLOOD TX" "$TMP" ||
    fail "No flooding packets found. Check that you ran the correct Cooja simulation."

  cut_line=$(awk '
    /NORMAL METRIC tx=5 rx=5/ {
      if ($0 ~ /ID:2[[:space:]]/) a=NR
      if ($0 ~ /ID:3[[:space:]]/) b=NR
      if ($0 ~ /ID:4[[:space:]]/) c=NR
    }
    END {
      if (a && b && c) {
        latest=a
        if (b > latest) latest=b
        if (c > latest) latest=c
        print latest
      }
    }
  ' "$TMP")

  [[ "$cut_line" =~ ^[0-9]+$ ]] ||
    fail "Flooding run is too short. Let Motes 2, 3 and 4 each complete 5 normal packets, then run this finish command again."

  head -n "$cut_line" "$TMP" > "$TRIM"
  mv "$TRIM" "$TMP"

  normal_tx=$(count_fixed "NORMAL TX" "$TMP")
  responses=$(count_fixed "RESPONSE seq=" "$TMP")
  flood_packets=$(count_fixed "FLOOD TX" "$TMP")

  (( normal_tx == 15 && responses == 15 )) ||
    fail "The common flooding comparison window is incomplete: normal TX=$normal_tx, responses=$responses. Keep the simulation running longer and retry."

  if [[ "$scenario" == flood_no_ids ]]; then
    (( flood_packets >= 2000 )) ||
      fail "Only $flood_packets flood packets were captured. The No-IDS run appears too short; run it longer and retry."

    if grep -Eq 'IDS ALERT: FLOODING DETECTED|IDS ACTION: source blacklisted and BLOCK sent|MITIGATION: BLOCK received from IDS|MITIGATION: attacker stopped' "$TMP"; then
      fail "IDS mitigation events appeared in the No-IDS run. Check the selected simulation."
    fi
  else
    for event in \
      "IDS ALERT: FLOODING DETECTED" \
      "IDS ACTION: source blacklisted and BLOCK sent" \
      "MITIGATION: BLOCK received from IDS" \
      "MITIGATION: attacker stopped"
    do
      grep -qF "$event" "$TMP" ||
        fail "Expected flooding IDS event missing: $event"
    done
  fi

else
  # Sinkhole runs should be captured through the attacker's stop event.
  grep -Eiq 'SINKHOLE|DIO|fake.rank' "$TMP" ||
    fail "No sinkhole activity found. Check the selected simulation."

  stop_line=$(grep -nF "SINKHOLE ATTACK STOPPED" "$TMP" | head -n 1 | cut -d: -f1 || true)

  [[ "$stop_line" =~ ^[0-9]+$ ]] ||
    fail "The sinkhole attack-stop event is missing. Let the simulation finish, then retry."

  head -n "$stop_line" "$TMP" > "$TRIM"
  mv "$TRIM" "$TMP"

  if [[ "$scenario" == sinkhole_ids ]]; then
    for event in \
      "IDS ALERT: SINKHOLE DETECTED" \
      "IDS ACTION: BLOCK sent to sinkhole" \
      "IDS ACTION: sinkhole node isolated" \
      "IDS ACTION: RPL global repair triggered" \
      "MITIGATION: BLOCK received from IDS" \
      "MITIGATION: sinkhole poisoned and leaving DAG"
    do
      grep -qF "$event" "$TMP" ||
        fail "Expected sinkhole IDS event missing: $event"
    done
  else
    if grep -Eiq 'IDS ALERT: SINKHOLE DETECTED|IDS ACTION: BLOCK sent to sinkhole|IDS ACTION: sinkhole node isolated|MITIGATION: BLOCK received from IDS' "$TMP"; then
      fail "IDS mitigation events appeared in the No-IDS run. Check the selected simulation."
    fi

    grep -qF "SINKHOLE DIO:" "$TMP" ||
      fail "No sinkhole DIO packets found in the No-IDS run."
  fi
fi

# Validation passed: archive the previous canonical log, then replace it.
stamp=$(date +"%Y-%m-%d_%H-%M-%S")
ARCHIVE="$ARCHIVES/${stamp}_${scenario}"
mkdir -p "$ARCHIVE"

if [[ -f "$LOG" ]]; then
  cp -p "$LOG" "$ARCHIVE/$(basename "$LOG")"
fi

mv "$TMP" "$LOG"
printf '%s\n' "$marker" > "$STATE"

echo
echo "======================================"
echo " EXPERIMENT SAVED SUCCESSFULLY"
echo "======================================"
echo "Scenario : $scenario"
echo "Log      : $LOG"
echo "Archive  : $ARCHIVE"

if [[ "$scenario" == flood_no_ids || "$scenario" == flood_ids ]]; then
  echo "Flood packets : $(count_fixed 'FLOOD TX' "$LOG")"
  echo "Normal TX     : $(count_fixed 'NORMAL TX' "$LOG")"
  echo "Responses     : $(count_fixed 'RESPONSE seq=' "$LOG")"
  echo "IDS alerts    : $(count_fixed 'IDS ALERT: FLOODING DETECTED' "$LOG")"
  echo "BLOCK actions : $(count_fixed 'IDS ACTION: source blacklisted and BLOCK sent' "$LOG")"
else
  echo "Sinkhole DIOs : $(count_fixed 'SINKHOLE DIO:' "$LOG")"
  echo "IDS alerts    : $(count_fixed 'IDS ALERT: SINKHOLE DETECTED' "$LOG")"
fi

echo
echo "Canonical log updated. You can proceed to the next experiment."
