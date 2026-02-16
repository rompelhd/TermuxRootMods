#!/system/bin/sh

BIN=$( [ -d /system/xbin ] && echo "/system/xbin" || echo "/system/bin" )
SDCARD=$( [ -d /sdcard ] && echo "/sdcard" || echo "/storage/emulated/0" )
ROOT_HOME="/data/data/com.termux/files/root-home"
TERMUX_BIN="/data/data/com.termux/files/usr/bin"
TERMUX_LIB="/data/data/com.termux/files/usr/lib"
TRM_LIBS_DIR="$TERMUX_LIB/trm_libs"
TRM_CONFIG="$ROOT_HOME/.config/TermuxRootMods"

ui_print "   Using SDCARD: $SDCARD"
ui_print "   Using ROOT_HOME: $ROOT_HOME"

if [ ! -d "$ROOT_HOME" ]; then
    mkdir -p "$ROOT_HOME"
    touch "$ROOT_HOME/.bash_history"
    ui_print "   Created ROOT_HOME and .bash_history"
fi

if [ -f "$ROOT_HOME/.aliases" ]; then
    ui_print "   Backing up existing .aliases to .aliases.bak"
    mv "$ROOT_HOME/.aliases" "$ROOT_HOME/.aliases.bak"
fi

cp "$MODPATH/custom/.aliases" "$ROOT_HOME/.aliases"
chmod 600 "$ROOT_HOME/.aliases"
ui_print "   Installed new .aliases in ROOT_HOME"

if [ ! -d "$TRM_CONFIG" ]; then
    mkdir -p "$TRM_CONFIG"
    cp "$MODPATH/custom/.trm" "$TRM_CONFIG/"
    ui_print "   Created TermuxRootMods config directory"
fi

ARCH=$(uname -m)

case $ARCH in
    aarch64) ARCH_DIR="arm64" ;;
    armv7l | armv8l) ARCH_DIR="armhf" ;;
    x86_64) ARCH_DIR="x86_64" ;;
    *)
        ui_print "   Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

ui_print "   Detected architecture: $ARCH_DIR"

copy_binary() {
    local src="$MODPATH/system/etc/arch/$ARCH_DIR/$1"
    local dest="$TERMUX_BIN/$1"

    if [ -f "$src" ]; then
        cp "$src" "$dest"
        chmod 755 "$dest"
        ui_print "   Installed $1"
    else
        ui_print "   $1 not found for $ARCH_DIR"
    fi
}

for file in servistatus temps cleaner fsu sudo trm; do
    copy_binary "$file"
done

# CLIBRARIES
BUILD_TRM_LIBS="$MODPATH/system/etc/arch/$ARCH_DIR/trm_libs"

mkdir -p "$TRM_LIBS_DIR"

if [ -d "$BUILD_TRM_LIBS" ]; then
    cp "$BUILD_TRM_LIBS/"* "$TRM_LIBS_DIR/"
    chmod 644 "$TRM_LIBS_DIR/"*
    ui_print "   Installed custom TRM libraries"
else
    ui_print "   No custom libraries found for $ARCH_DIR"
fi

# MAGISK OVERLAY
cp -f "$MODPATH/system/etc/mkshrc" "$MODPATH/system/etc/mkshrc"
chmod 644 "$MODPATH/system/etc/mkshrc"

cp -f "$MODPATH/system/etc/arch/$ARCH_DIR/shell" \
      "$MODPATH/system/etc/shell"
chmod 755 "$MODPATH/system/etc/shell"

ui_print "   Magisk overlay prepared"

ui_print "   Installation complete ✔"
