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

import keystone
import capstone


class BasePatcher():
    def __init__(self, data):
        self.data = bytearray(data)
        self.ks = keystone.Ks(keystone.KS_ARCH_ARM, keystone.KS_MODE_THUMB)
        self.cs = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)

    def asm(self, x):
        pre = bytes(self.ks.asm(x)[0])
        return pre

    def disasm(self, pre):
        pre_dis = [' '.join([x.bytes.hex(), x.mnemonic, x.op_str])
                   for x in self.cs.disasm(pre, 0)]
        return pre_dis

    def ret_val(self, descr, ofs, pre, post):
        return [(descr, hex(ofs), pre.hex(), post.hex())]

    def dpc(self):
        raise NotImplementedError()

    def remove_kers(self):
        raise NotImplementedError()

    def remove_autobrake(self):
        raise NotImplementedError()

    def remove_charging_mode(self):
        raise NotImplementedError()

    def current_raising_coeff(self, coeff):
        raise NotImplementedError()

    def speed_limit_ped(self, kmh):
        raise NotImplementedError()

    def speed_limit_drive(self, kmh):
        raise NotImplementedError()

    def speed_limit_sport(self, kmh):
        raise NotImplementedError()

    def ampere_ped(self, amps, force=False):
        raise NotImplementedError()

    def ampere_drive(self, amps, force=True):
        raise NotImplementedError()

    def ampere_sport(self, amps, force=True):
        raise NotImplementedError()

    def ampere_max(self, amps_ped=None, amps_drive=None, amps_sport=None):
        raise NotImplementedError()

    def ampere_brake(self, min_=None, max_=None):
        raise NotImplementedError()

    def motor_start_speed(self, kmh):
        raise NotImplementedError()

    def wheel_speed_const(self, factor):
        raise NotImplementedError()

    def shutdown_time(self, seconds):
        raise NotImplementedError()

    def brake_light_static(self):
        raise NotImplementedError()

    def region_free(self):
        raise NotImplementedError()

    def bms_baudrate(self, val):
        raise NotImplementedError()

    def volt_limit(self, volts):
        raise NotImplementedError()
