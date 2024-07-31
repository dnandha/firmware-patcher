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

from base_patcher import BasePatcher
from util import FindPattern


class NbPatcher(BasePatcher):
    def __init__(self, data):
        super().__init__(data)

    def disable_motor_ntc(self):
        sig = self.asm('movs r0, #0x29')
        ofs = FindPattern(self.data, sig) + len(sig)
        pre = self.data[ofs:ofs+4]
        post = self.asm('nop.w')
        self.data[ofs:ofs+4] = post

        return self.ret_val("disable_motor_ntc", ofs, pre, post)
