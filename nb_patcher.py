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
    def __init__(self, data, model):
        super().__init__(data, model)

    def disable_motor_ntc(self):
        '''
        Creator/Author: NandTek
        Description: Disables error 41, which is thrown when motor NTC is missing
        '''
        sig = self.asm('movs r0, #0x29')
        ofs = FindPattern(self.data, sig) + len(sig)
        pre = self.data[ofs:ofs+4]
        post = self.asm('nop.w')
        self.data[ofs:ofs+4] = post

        return self.ret_val("disable_motor_ntc", ofs, pre, post)

    def region_free(self):
        '''
        Creator/Author: NandTek
        Description: Set global region
        '''
        sig = self.asm('cmp r0, #0x4e')
        ofs = FindPattern(self.data, sig, start=0x8000) + len(sig)

        if self.model == "f2pro":
            sig = self.asm('strb.w r4,[r7,#0x4f]')
            ofs_dst = FindPattern(self.data, sig, start=0x8000)
            assert ofs_dst == 0x97e6, hex(ofs_dst)
        elif self.model == "f2plus":
            sig = self.asm('strb.w r4,[r7,#0x59]')
            ofs_dst = FindPattern(self.data, sig, start=0x8000)
            assert ofs_dst == 0x989e, hex(ofs_dst)
        elif self.model == "f2":
            sig = self.asm('strb.w r4,[r7,#0x61]')
            ofs_dst = FindPattern(self.data, sig, start=0x8000)
            assert ofs_dst == 0x995a, hex(ofs_dst)

        pre = self.data[ofs:ofs+2]
        post = self.asm(f'b #{ofs_dst-ofs}')
        self.data[ofs:ofs+2] = post

        return self.ret_val("region_free", ofs, pre, post)
