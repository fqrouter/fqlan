adb push fqlan.py /sdcard/fqlan.py
adb shell su -c "python /sdcard/fqlan.py --lan-interface wlan0 --ifconfig-path /data/data/fq.router/busybox scan 10.45.30.0/24"