#!/system/bin/sh

BIN=$( [ -d /system/xbin ] && echo "/system/xbin" || echo "/system/bin" )
SDCARD=$( [ -d /sdcard ] && echo "/sdcard" || echo "/storage/emulated/0" )
ROOT_HOME="/data/data/com.termux/files/root-home"
Temuxrootmods="$ROOT_HOME/.config/TermuxRootMods/"

touch "$SDCARD/.customrc"

if [ ! -d "$ROOT_HOME" ]; then
    mkdir -p "$ROOT_HOME"
    touch "$ROOT_HOME/.bash_history"
    ui_print "   Created root home folder and .bash_history"
fi

# ROOT_HOME
if [ -f "$ROOT_HOME/.aliases" ]; then
    ui_print "   $ROOT_HOME/.aliases found! Backing up to .aliases.bak"
    mv "$ROOT_HOME/.aliases" "$ROOT_HOME/.aliases.bak"
fi

# New .aliases
ui_print "   Installing default .aliases from module to home root"
cp "$MODPATH/custom/.aliases" "$ROOT_HOME/.aliases"

# SDCard
if [ -f "$SDCARD/.aliases" ]; then
    ui_print "   $SDCARD/.aliases found! Backing up to .aliases.baksdcard"
    mv "$SDCARD/.aliases" "$ROOT_HOME/.aliases.baksdcard"
fi

if [ ! -d "$Temuxrootmods" ]; then
    mkdir -p "$Temuxrootmods"
    cp "$MODPATH/custom/.trm" "$Temuxrootmods"
    ui_print "   Created TermuxRootMods Config on /root-home/.config/TermuxRootMods/"
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

for file in servistatus temps cleaner fsu sudo; do
    copy_file_if_exists "$file"
done

cp -f "$MODPATH/system/etc/mkshrc" "$MODPATH/system/etc/mkshrc"
chmod 777 "$MODPATH/system/etc/mkshrc"

cp -f "$MODPATH/system/etc/arch/$ARCH_DIR/shell" "$MODPATH/system/etc/shell"
chmod 777 "$MODPATH/system/etc/shell"

ui_print "   mkshrc copied to Magisk overlay"
