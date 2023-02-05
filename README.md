# NextGen firmware patcher
Little firmware modifications to make your day  nicer.

I wrote this patcher based on BotoX [m365 firmware patcher](https://github.com/BotoX/xiaomi-m365-firmware-patcher).

New mods / contributions highly welcome, simply open PR and present your mod!
The mod will then be integrated into the XNG patcher.

## Supported DRVs
* DRV016
* DRV017
* DRV242
* DRV245
* DRV247
* DRV248
* DRV252
* DRV319
* DRV321

## Available Mods
* DPC (register)
* No KERS (improved)
* No Charging Fix
* Remove Speed Check
* Shutdown Time
* Motor Start Speed
* Cruise Control Delay
* Current Raising Coefficient
* Wheelsize
* Speed Limits
* Phase Currents
* Current Meter
* Region Free
* Brakelight / Auto-Light
* (Lever resolution (gas/brake))
* Remove Model Lock

## Instructions
1. `FLASK_APP=app/__init__.py`
2. `flask run` to start the flask app

## License
Licensed under AGPLv3 (see LICENSE.md)
