#!/system/bin/sh

MODDIR=${0%/*}
sed -i "s/^description=.*/description=ForgeMint KeyMint attestation hook demo/" "$MODDIR/module.prop"

while true; do
  PID=$(pidof keystore2)
  [ -n "$PID" ] && "$MODDIR/bin/injector" "$PID" "$MODDIR"
  sleep 2
done &
