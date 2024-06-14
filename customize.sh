#!/system/bin/sh

[ -d /system/xbin ] && BIN=/system/xbin || BIN=/system/bin
if [ -d /sdcard ]; then
  SDCARD=/sdcard
elif [ -d /storage/emulated/0 ]; then
  SDCARD=/storage/emulated/0
fi
ui_print "   Setting $SDCARD location."

mkdir -p $SDCARD/TermuxRootMods
ui_print "   Created /sdcard/TermuxRootMods folder."

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
else
  ui_print "   Root home folder exists"
fi

if [ -f $MODPATH/system/etc/servistatus ]; then
  cp $MODPATH/system/etc/servistatus /data/data/com.termux/files/usr/bin
  chmod +x /data/data/com.termux/files/usr/bin/servistatus
  ui_print "   Servistatus copied and set executable permission on com.termux/files/usr/bin"
else
  ui_print "   Servistatus not found in /system/etc."
fi

if [ -f $MODPATH/system/etc/temps ]; then
  cp $MODPATH/system/etc/temps /data/data/com.termux/files/usr/bin
  chmod +x /data/data/com.termux/files/usr/bin/temps
  ui_print "   Temps copied and set executable permission on com.termux/files/usr/bin"
else
  ui_print "   Temps not found in /system/etc."
fi
