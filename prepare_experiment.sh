#!/usr/bin/env bash

set -e

PROJECT_DIR="$HOME/secure-iot-ids"
ARCHIVE_ROOT="$PROJECT_DIR/experiment_archive"

scenario="${1:-}"

case "$scenario" in

  normal)
    LOG_FILE="normal_log.txt"
    CSC_FILE="$PROJECT_DIR/Secure_IoT_Normal.csc"
    DESCRIPTION="Normal baseline"
    ;;

  flood_no_ids)
    LOG_FILE="flood_no_ids_log.txt"
    CSC_FILE="$PROJECT_DIR/Secure_IoT_Flooding_No_IDS.csc"
    DESCRIPTION="Flooding attack WITHOUT IDS"
    ;;

  flood_ids)
    LOG_FILE="flood_ids_log.txt"
    CSC_FILE="$PROJECT_DIR/Secure_IoT_Flooding_Final.csc"
    DESCRIPTION="Flooding attack WITH IDS"
    ;;

  sinkhole_no_ids)
    LOG_FILE="sinkhole_no_ids_log.txt"
    CSC_FILE="$PROJECT_DIR/sinkhole/Secure_IoT_Sinkhole_No_IDS.csc"
    DESCRIPTION="Sinkhole attack WITHOUT IDS (development baseline)"
    ;;

  sinkhole_ids)
    LOG_FILE="sinkhole_fast_ids_final_log.txt"
    CSC_FILE="$PROJECT_DIR/sinkhole_fast_ids/Secure_IoT_Sinkhole_IDS_Final.csc"
    DESCRIPTION="Sinkhole attack WITH IDS"
    ;;

  *)
    echo
    echo "Usage:"
    echo "  ./prepare_experiment.sh normal"
    echo "  ./prepare_experiment.sh flood_no_ids"
    echo "  ./prepare_experiment.sh flood_ids"
    echo "  ./prepare_experiment.sh sinkhole_no_ids"
    echo "  ./prepare_experiment.sh sinkhole_ids"
    echo
    exit 1
    ;;
esac

if [ ! -f "$CSC_FILE" ]; then
  echo
  echo "ERROR: Cooja simulation file not found:"
  echo "$CSC_FILE"
  exit 1
fi

TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
ARCHIVE_DIR="$ARCHIVE_ROOT/runs/${TIMESTAMP}_${scenario}"

mkdir -p "$ARCHIVE_DIR"

echo
echo "============================================================"
echo " PREPARING EXPERIMENT"
echo "============================================================"
echo "Scenario : $DESCRIPTION"
echo "Log file : $PROJECT_DIR/$LOG_FILE"
echo "Cooja    : $CSC_FILE"
echo

if [ -f "$PROJECT_DIR/$LOG_FILE" ]; then
  cp -v "$PROJECT_DIR/$LOG_FILE" "$ARCHIVE_DIR/$LOG_FILE"
  echo "Archived previous log:"
  echo "  $ARCHIVE_DIR/$LOG_FILE"
else
  echo "No previous canonical log found."
fi

: > "$PROJECT_DIR/$LOG_FILE"

echo
echo "Fresh canonical log created:"
echo "  $PROJECT_DIR/$LOG_FILE"

echo
echo "============================================================"
echo " OPEN THIS EXACT COOJA SIMULATION"
echo "============================================================"
echo "$CSC_FILE"

echo
echo "============================================================"
echo " RUN PROCEDURE"
echo "============================================================"
echo "1. Open the exact .csc file above in Cooja."
echo "2. Run the simulation."
echo "3. Save/export the resulting output to:"
echo "   $PROJECT_DIR/$LOG_FILE"
echo "4. Verify the log after the simulation."
echo

if [ "$scenario" = "sinkhole_no_ids" ]; then
  echo "NOTE:"
  echo "This is the older/development Sinkhole No-IDS baseline."
  echo "Do not treat it as the final clean comparison unless verified."
  echo
fi

echo "Preparation complete."
echo "============================================================"
