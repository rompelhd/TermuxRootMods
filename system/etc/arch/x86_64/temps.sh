#!/system/bin/sh

THERMAL_DIR="/sys/class/thermal/"

if [ ! -d "$THERMAL_DIR" ]; then
    echo "Error: Directory Thermal not found."
    exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "Maybe you need root, depending on the Android device and manufacturer."
fi

printf "+--------------------+-------------------+\n"
printf "| %-18s | %-18s |\n" "Type" "Temp (°C)"
printf "+--------------------+-------------------+\n"

for ZONE in $(ls "$THERMAL_DIR" | grep "thermal_zone"); do
    TYPE_FILE="$THERMAL_DIR$ZONE/type"
    TEMP_FILE="$THERMAL_DIR$ZONE/temp"

    if [ -f "$TYPE_FILE" ] && [ -f "$TEMP_FILE" ]; then
        TEMP=$(cat "$TEMP_FILE" 2>/dev/null)
        TEMP_C=$(awk "BEGIN { printf \"%.1f\", $TEMP / 1000 }" 2>/dev/null)

        if awk "BEGIN { exit !($TEMP > 0) }"; then
            TYPE=$(cat "$TYPE_FILE" 2>/dev/null)
            printf "| %-18s | %-17s |\n" "$TYPE" "$TEMP_C"
        fi
    fi
done

printf "+--------------------+-------------------+\n"
