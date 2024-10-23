#!/system/bin/sh

cleaner() {
    clear
    echo "Cleaning apps cache..."

    local logs1="[$(date +'%d/%m/%y %H:%M:%S')] Cleaning apps cache... (TermuxRootMods)"
    echo $logs1 >> /sdcard/logs.txt

    clean_cache_app() {
        local app_dir=$1
        local app_name=$(basename "$app_dir")
        local cache_size=$(du -sh "$app_dir/cache" 2>/dev/null | cut -f1)
        local code_cache_size=$(du -sh "$app_dir/code_cache" 2>/dev/null | cut -f1)

        if [ -n "$cache_size" ] || [ -n "$code_cache_size" ]; then
            echo "Deleting cache for $app_name (Cache: ${cache_size:-0}, Code Cache: ${code_cache_size:-0})..."
            echo "[$(date +'%d/%m/%y %H:%M:%S')] Deleting cache for $app_name (Cache: ${cache_size:-0}, Code Cache: ${code_cache_size:-0})" >> /sdcard/logs.txt
            find "$app_dir/cache"/* -delete >/dev/null 2>&1 | tee -a /sdcard/logs.txt
            find "$app_dir/code_cache"/* -delete >/dev/null 2>&1 | tee -a /sdcard/logs.txt
        fi
    }

    echo "Deleting files from /data/data/*/cache and /data/data/*/code_cache..."
    for app_dir in /data/data/*; do
        clean_cache_app "$app_dir"
    done

    echo "Deleting files from /data/user_de/*/*/cache and /data/user_de/*/*/code_cache..."
    for app_dir in /data/user_de/*/*; do
        clean_cache_app "$app_dir"
    done

    echo "Deleting files from /sdcard/Android/data/*/cache..."
    for app_dir in /sdcard/Android/data/*; do
        local app_name=$(basename "$app_dir")
        local cache_size=$(du -sh "$app_dir/cache" >/dev/null 2>&1 | cut -f1)
        if [ -n "$cache_size" ]; then
            echo "Deleting cache for $app_name (Cache: ${cache_size:-0})..."
            echo "[$(date +'%d/%m/%y %H:%M:%S')] Deleting cache for $app_name (Cache: ${cache_size:-0})" >> /sdcard/logs.txt
            find "$app_dir/cache"/* -delete >/dev/null 2>&1 | tee -a /sdcard/logs.txt
        fi
    done

    local logs2="[$(date +'%d/%m/%y %H:%M:%S')] Done! The apps cache has been cleaned!\n"
    echo -e $logs2 >> /sdcard/logs.txt

    echo "Done! The apps cache has been cleaned!"
}

if [ "$(whoami)" != "root" ]; then
    echo "Run this command with root privileges!"
else
    clear
    echo "Running script..."
    cleaner
fi
