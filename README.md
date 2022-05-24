# VLT Firmware patcher
Little firmware modifications to make your day  nicer.
Check out [VLT Mods](https://rollerplausch.com/threads/vlt-firmwares-in-de-22kmh-mit-neuster-vanilla-firmware-und-vieles-mehr.3197/).

I wrote this patcher based on BotoX [m365 firmware patcher](https://github.com/BotoX/xiaomi-m365-firmware-patcher).

## Supported DRVs
* DRV236
* DRV247
* DRV248
* DRV309
* DRV319
* DRV321

## Available Mods
* Brakelight
* Speed limits
* Amps / Phase currents
* Current raising coefficient
* Motor start speed
* No charging fix
* 30km/h speed check
* Wheelsize
* Shutdown time
* Cruise control delay
* DPC (register)
* LTGM (register)
* ReLight Mod: Set/Reset, Beep, Delay, AutoLight
* DKC (replaces "No KERS")
* Pedestrian unlock
* Lower light
* Amperemeter
* (Lever resolution (gas/brake))
* (Brake start speed)
* Region unlocks: Cruise control, Backlight, German brake

## Instructions
1. `FLASK_APP=app/__init__.py`
2. `flask run` to start the flask app

## License
Licensed under AGPLv3 (see LICENSE.md)
