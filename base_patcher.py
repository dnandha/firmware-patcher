#!/usr/bin/python3
#
# NGFW Patcher
# Copyright (C) 2021-2024 Daljeet Nandha
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#

from enum import Enum
import keystone
import capstone

class PatchGroup(Enum):
    GENERAL = "general"
    SPEED = "speed"
    AMPERE = "ampere"

def patch(label, description, group, min=None, max=None):
    def decorator(func):
        func.label = label
        func.description = description
        func.group = group
        func.min = min
        func.max = max
        return func
    return decorator

class BasePatcher():
    def __init__(self, data, model):
        self.data = bytearray(data)
        self.ks = keystone.Ks(keystone.KS_ARCH_ARM, keystone.KS_MODE_THUMB)
        self.cs = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)

        self.model = model

        self.defaults = {
            "dummy": {
                "speed_limit_ped": 20,
                "speed_limit_drive": 25,
                "speed_limit_sport": 30,
                "ampere_ped": 5000,
                "ampere_drive": 15000,
                "ampere_sport": 20000,
                "ampere_ped_max": 10000,
                "ampere_drive_max": 25000,
                "ampere_sport_max": 35000,
                "ampere_brake_min": 5000,
                "ampere_brake_max": 50000,
                "volt_limit": 43.01,
                "current_raising_coeff": 600,
                "motor_start_speed": 5.0,
                "wheel_speed_const": 1.0,
                "shutdown_time": 3.0,
                "cc_delay": 5.0,
                "wheel_size": 8.5
            }
        }
    
    def get_defaults(self, device):
        return self.defaults.get(device, {})

    def asm(self, x):
        pre = bytes(self.ks.asm(x)[0])
        return pre

    def disasm(self, pre):
        pre_dis = [' '.join([x.bytes.hex(), x.mnemonic, x.op_str])
                   for x in self.cs.disasm(pre, 0)]
        return pre_dis

    def ret(self, descr, ofs, pre, post):
        return [(descr, hex(ofs), pre.hex(), post.hex())]

    @patch(label="dpc",
           description="Activate/Deactivate DPC via register.",
           group=PatchGroup.GENERAL)
    def dpc(self):
        raise NotImplementedError()

    @patch(label="remove_kers",
           description="Deactivates KERS (kinetic energy recuperation system).",
           group=PatchGroup.GENERAL)
    def remove_kers(self):
        raise NotImplementedError()

    @patch(label="remove_autobrake",
           description="Remove automatic braking at certain speeds.",
           group=PatchGroup.GENERAL)
    def remove_autobrake(self):
        raise NotImplementedError()

    @patch(label="remove_charging_mode",
           description="Ignore input from charging line.",
           group=PatchGroup.GENERAL)
    def remove_charging_mode(self):
        raise NotImplementedError()

    @patch(label="brake_light_static",
           description="Replaces the blinking backlight by a static backlight on braking.",
           group=PatchGroup.GENERAL)
    def brake_light_static(self):
        raise NotImplementedError()

    @patch(label="region_free",
           description="Remove regional restrictions normally imposed by the serial number.",
           group=PatchGroup.GENERAL)
    def region_free(self):
        raise NotImplementedError()

    @patch(label="bms_baudrate",
           description="Set BMS baudrate to 76800 as required for OpenSource BMS.",
           group=PatchGroup.GENERAL)
    def bms_baudrate(self, val=76800):
        raise NotImplementedError()

    @patch(label="volt_limit",
           description="Change when connecting a custom battery with a different voltage.",
           group=PatchGroup.GENERAL,
           min=10, max=100)
    def volt_limit(self, volts=43.01):
        raise NotImplementedError()

    @patch(label="current_raising_coeff",
           description="Current raising coefficient, defines the increments of current increase.",
           group=PatchGroup.GENERAL,
           min=0, max=2000)
    def current_raising_coeff(self, coeff):
        raise NotImplementedError()

    @patch(label="motor_start_speed",
           description="Minimum required speed before the motor will start.",
           group=PatchGroup.GENERAL,
           min=0, max=10)
    def motor_start_speed(self, kmh=5.0):
        raise NotImplementedError()

    @patch(label="wheel_speed_const",
           description="With different wheels, adjust this to match the GPS speed and torque.",
           group=PatchGroup.GENERAL,
           min=0.5, max=2)
    def wheel_speed_const(self, factor=1.0):
        raise NotImplementedError()

    @patch(label="shutdown_time",
           description="Time you have to press the power button until the device turns off.",
           group=PatchGroup.GENERAL,
           min=0, max=10)
    def shutdown_time(self, seconds=3.0):
        raise NotImplementedError()

    @patch(label="cc_delay",
           description="Time needed for cruise control to kick in.",
           group=PatchGroup.GENERAL,
           min=0, max=10)
    def cc_delay(self, seconds=5.0):
        raise NotImplementedError()

    @patch(label="speed_limit_ped",
           description="Speed limit for pedestrian mode.",
           group=PatchGroup.SPEED,
           min=0, max=65)
    def speed_limit_ped(self, kmh):
        raise NotImplementedError()

    @patch(label="speed_limit_drive",
           description="Speed limit for drive mode.",
           group=PatchGroup.SPEED,
           min=0, max=65)
    def speed_limit_drive(self, kmh):
        raise NotImplementedError()

    @patch(label="speed_limit_sport",
           description="Speed limit for sport mode.",
           group=PatchGroup.SPEED,
           min=0, max=65)
    def speed_limit_sport(self, kmh):
        raise NotImplementedError()

    @patch(label="ampere_ped",
           description="Ampere for pedestrian mode.",
           group=PatchGroup.AMPERE,
           min=0, max=35000)
    def ampere_ped(self, amps, force=False):
        raise NotImplementedError()

    @patch(label="ampere_drive",
           description="Ampere for drive mode.",
           group=PatchGroup.AMPERE,
           min=0, max=35000)
    def ampere_drive(self, amps, force=True):
        raise NotImplementedError()

    @patch(label="ampere_sport",
           description="Ampere for sport mode.",
           group=PatchGroup.AMPERE,
           min=0, max=35000)
    def ampere_sport(self, amps, force=True):
        raise NotImplementedError()

    @patch(label="ampere_max",
           description="Maximum ampere for all three modes.",
           group=PatchGroup.AMPERE,
           min=0, max=65000)
    def ampere_max(self, amps_ped=None, amps_drive=None, amps_sport=None):
        raise NotImplementedError()

    @patch(label="ampere_brake",
           description="Ampere for brake lever.",
           group=PatchGroup.AMPERE,
           min=0, max=65000)
    def ampere_brake(self, min_=None, max_=None):
        raise NotImplementedError()