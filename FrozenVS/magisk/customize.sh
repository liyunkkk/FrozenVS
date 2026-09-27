$BOOTMODE || abort "- 安装失败，仅支持在 Magisk 或 KernelSU 下安装"

chmod a+x "$MODPATH"/Frozen
chmod a+x "$MODPATH"/service.sh

pm uninstall cn.myflv.android.noanr >/dev/null 2>&1
for pkg in cn.myflv.android.noactive com.github.uissd.miller com.github.f19f.milletts \
           com.ff19.mitlite com.sidesand.millet nep.timeline.freezer com.mubei.android; do
  [ -n "$(pm list packages "$pkg")" ] && echo "- 冲突模块 $pkg，请到 LSPosed 禁用"
done
pm uninstall io.github.jark006.freezeit >/dev/null 2>&1
[ -e /data/adb/modules/mubei ] && touch /data/adb/modules/mubei/disable
[ -e /data/adb/modules/Hc_tombstone ] && touch /data/adb/modules/Hc_tombstone/disable

for f in appcfg.txt applabel.txt settings.db; do
  [ -e "/data/adb/modules/Frozen/$f" ] && cp -f "/data/adb/modules/Frozen/$f" "$MODPATH"
done

module_version="$(grep_prop version "$MODPATH"/module.prop)"
apkPath=/data/local/tmp/Frozen.apk
mv -f "$MODPATH"/Frozen.apk "$apkPath"
chmod 666 "$apkPath"

output=$(pm install -r -f "$apkPath" 2>&1)
if [ "$output" != "Success" ]; then
  pm uninstall io.github.MoWei.Frozen >/dev/null 2>&1
  sleep 1
  output=$(pm install -r -f "$apkPath" 2>&1)
fi

if [ "$output" == "Success" ]; then
  rm -f "$apkPath"
else
  cp -f "$apkPath" "/sdcard/Frozen_${module_version}.apk"
  echo "! APP 安装失败，请手动安装 /sdcard/Frozen_${module_version}.apk"
fi
