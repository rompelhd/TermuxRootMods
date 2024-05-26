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
