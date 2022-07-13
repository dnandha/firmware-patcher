# NextGen firmware patcher
Little firmware modifications to make your day  nicer.

I wrote this patcher based on BotoX [m365 firmware patcher](https://github.com/BotoX/xiaomi-m365-firmware-patcher).

## Supported DRVs
* DRV016
* DRV242
* DRV247
* DRV248
* DRV319
* DRV321

## Available Mods
* DPC (register)
* No KERS (improved)
* No charging fix
* Remove speed check
* Shutdown time
* Motor start speed
* Cruise control delay
* Current raising coefficient
* Wheelsize
* Speed limits
* Phase currents
* Current Meter
* Region Free
* Brakelight / Auto-Light
* (Lever resolution (gas/brake))

## Instructions
1. `FLASK_APP=app/__init__.py`
2. `flask run` to start the flask app

## License
Licensed under AGPLv3 (see LICENSE.md)
