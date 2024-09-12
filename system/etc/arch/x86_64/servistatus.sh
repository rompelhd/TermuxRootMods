#!/bin/sh

checkroot() {
if [ "$(id -u)" -ne 0 ]; then
  echo "U need root for using. Exiting..."
  exit 1
fi
}

list_services() {
    echo "Listing all available services in table format:"
    services=$(dumpsys -l)

    sorted_services=$(echo "$services" | awk '{ print length, $0 }' | sort -n | cut -d" " -f2-)

    column_count=4
    current_column=0

    for service in $sorted_services; do
        printf "%-25s" "$service"
        current_column=$((current_column + 1))

        if [ $current_column -ge $column_count ]; then
            echo
            current_column=0
        fi
    done

    if [ $current_column -ne 0 ]; then
        echo
    fi
}

show_service_info() {
    local service_name=$1
    if [ -z "$service_name" ]; then
        echo "Please provide a service name to show details."
        return 1
    fi
    dumpsys $service_name
}

if [ "$#" -eq 0 ]; then
    checkroot
    list_services
    echo "Usage: $0 [service_name]"
elif [ "$1" = "--help" ]; then
    echo "Usage: $0 [service_name]"
    echo "Options:"
    echo "  service_name  Display details of the specified service"
    echo "  --help        Show this help message"
else
    checkroot
    show_service_info $1
fi
