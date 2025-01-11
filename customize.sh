#!/system/bin/sh

[ -d /system/xbin ] && BIN=/system/xbin || BIN=/system/bin
if [ -d /sdcard ]; then
  SDCARD=/sdcard
elif [ -d /storage/emulated/0 ]; then
  SDCARD=/storage/emulated/0
fi
ui_print "   Setting $SDCARD location."

sed -i "s|<SDCARD>|$SDCARD|g" $MODPATH/system/etc/mkshrc

touch $SDCARD/.customrc
if [ ! -f $SDCARD/.aliases ]; then
  ui_print "   Copying .aliases to $SDCARD"
  cp $MODPATH/custom/.aliases $SDCARD
else
  ui_print "   $SDCARD/.aliases found! Backing up and overwriting!"
  cp -rf $SDCARD/.aliases $SDCARD/.aliases.bak
  cp -rf $MODPATH/custom/.aliases $SDCARD
fi

if [ ! -d /data/data/com.termux/files/root-home ]; then
  mkdir /data/data/com.termux/files/root-home
  ui_print "   Created root home folder"
  touch /data/data/com.termux/files/root-home/.bash_history
  ui_print "   Created .bash_history in root home folder"
else
  ui_print "   Root home folder exists"
fi

ARCH=$(uname -m)
ui_print "   Detected architecture: $ARCH"

case $ARCH in
  aarch64)
    ARCH_DIR="arm64"
    ;;
  armv7l | armv8l)
    ARCH_DIR="armhf"
    ;;
  x86_64)
    ARCH_DIR="x86_64"
    ;;
  *)
    ui_print "   Unsupported architecture: $ARCH"
    exit 1
    ;;
esac

if [ -f $MODPATH/system/etc/arch/$ARCH_DIR/servistatus ]; then
  cp $MODPATH/system/etc/arch/$ARCH_DIR/servistatus /data/data/com.termux/files/usr/bin
  chmod +x /data/data/com.termux/files/usr/bin/servistatus
  ui_print "   Servistatus copied and set executable permission on /data/data/com.termux/files/usr/bin"
else
  ui_print "   Servistatus not found in $MODPATH/$ARCH_DIR/"
fi

if [ -f $MODPATH/system/etc/arch/$ARCH_DIR/temps ]; then
  cp $MODPATH/system/etc/arch/$ARCH_DIR/temps /data/data/com.termux/files/usr/bin
  chmod +x /data/data/com.termux/files/usr/bin/temps
  ui_print "   Temps copied and set executable permission on /data/data/com.termux/files/usr/bin"
else
  ui_print "   Temps not found in $MODPATH/$ARCH_DIR/"
fi

if [ -f $MODPATH/system/etc/arch/$ARCH_DIR/cleaner  ]; then
  cp $MODPATH/system/etc/arch/$ARCH_DIR/cleaner /data/data/com.termux/files/usr/bin
  chmod +x /data/data/com.termux/files/usr/bin/cleaner
  ui_print "   Cleaner copied and set executable permission on /data/data/com.termux/files/usr/bin"
else
  ui_print "   Cleaner not found in $MODPATH/$ARCH_DIR/"
fi

if [ -f $MODPATH/system/etc/arch/$ARCH_DIR/fsu  ]; then
  cp $MODPATH/system/etc/arch/$ARCH_DIR/fsu /data/data/com.termux/files/usr/bin
  chmod +x /data/data/com.termux/files/usr/bin/fsu
  ui_print "   Fsu copied and set executable permission on /data/data/com.termux/files/usr/bin"
else
  ui_print "   Fsu not found in $MODPATH/$ARCH_DIR/"
fi

fsu
