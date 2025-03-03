#!/system/bin/sh

BIN=$( [ -d /system/xbin ] && echo "/system/xbin" || echo "/system/bin" )
SDCARD=$( [ -d /sdcard ] && echo "/sdcard" || echo "/storage/emulated/0" )
ROOT_HOME="/data/data/com.termux/files/root-home"

ui_print "   Setting SDCARD location: $SDCARD"
sed -i "s|<SDCARD>|$SDCARD|g" "$MODPATH/system/etc/mkshrc"

touch "$SDCARD/.customrc"

if [ -f "$SDCARD/.aliases" ]; then
    ui_print "   $SDCARD/.aliases found! Backing up and overwriting!"
    mv "$SDCARD/.aliases" "$SDCARD/.aliases.bak"
fi
cp "$MODPATH/custom/.aliases" "$SDCARD"

if [ ! -d "$ROOT_HOME" ]; then
    mkdir -p "$ROOT_HOME"
    touch "$ROOT_HOME/.bash_history"
    ui_print "   Created root home folder and .bash_history"
fi

ARCH=$(uname -m)
case $ARCH in
    aarch64) ARCH_DIR="arm64" ;;
    armv7l | armv8l) ARCH_DIR="armhf" ;;
    x86_64) ARCH_DIR="x86_64" ;;
    *) ui_print "   Unsupported architecture: $ARCH"; exit 1 ;;
esac

copy_file_if_exists() {
    local src="$MODPATH/system/etc/arch/$ARCH_DIR/$1"
    local dest="/data/data/com.termux/files/usr/bin/$1"
    if [ -f "$src" ]; then
        cp "$src" "$dest"
        chmod +x "$dest"
        ui_print "   $1 copied and set executable permission on $dest"
    else
        ui_print "   $1 not found in $MODPATH/$ARCH_DIR/"
    fi
}

for file in servistatus temps cleaner fsu; do
    copy_file_if_exists "$file"
done
