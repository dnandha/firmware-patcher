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
        '''
        OP: Turbojeet
        Description: Disables error 41, which is thrown when motor NTC is missing
        '''
        sig = self.asm('movs r0, #0x29')
        ofs = FindPattern(self.data, sig) + len(sig)
        pre = self.data[ofs:ofs+4]
        post = self.asm('nop.w')
        self.data[ofs:ofs+4] = post

        return self.ret("disable_motor_ntc", ofs, pre, post)
    
    def skip_key_check(self):
        '''
        OP: WallyCZ
        Description: Skips key check
        '''
        sig = self.asm('ldrb.w r12,[r12,#0x5]')
        ofs = FindPattern(self.data, sig)
        sig = self.asm('cmp r0, #0x10')
        ofs = FindPattern(self.data, sig, start=ofs) + 4

        sig = self.asm('strb.w r11,[r6,#0x5]')
        ofs_dst = FindPattern(self.data, sig, start=ofs) - 2

        pre = self.data[ofs:ofs+2]
        post = self.asm(f'b #{ofs_dst-ofs}')
        self.data[ofs:ofs+2] = post

        return self.ret("skip_key_check", ofs, pre, post)

    def allow_sn_change(self):
        '''
        OP: WallyCZ
        Description: Allows changing the serial number
        '''
        sig = self.asm('ldrb.w r0,[r8,#0x4a]')
        ofs = FindPattern(self.data, sig)
        pre = self.data[ofs:ofs+4]
        post = self.asm('mov.w r0, #0x1')
        self.data[ofs:ofs+4] = post

        return self.ret("allow_sn_change", ofs, pre, post)

    def region_free(self):
        res = []

        # 1.4.15
        sig = self.asm('cmp r1, #0x56')
        ofs = FindPattern(self.data, sig) + len(sig)
        pre = self.data[ofs:ofs+2]
        post = b'\xf0\xd0'  # beq -> global
        res += self.ret("region_free_pro_0", ofs, pre, post)

        sig = self.asm('cmp r1, #0x55')
        ofs = FindPattern(self.data, sig, start=ofs) + len(sig)
        pre = self.data[ofs:ofs+2]
        post = b'\xdd\xd0'
        res += self.ret("region_free_pro_1", ofs, pre, post)

        sig = self.asm('cmp r1, #0x54')
        ofs = FindPattern(self.data, sig, start=ofs) + len(sig)
        pre = self.data[ofs:ofs+2]
        post = b'\xca\xd0'
        res += self.ret("region_free_pro_2", ofs, pre, post)

        sig = self.asm('cmp r1, #0x53')
        ofs = FindPattern(self.data, sig, start=ofs) + len(sig)
        pre = self.data[ofs:ofs+2]
        post = b'\xb8\xd0'
        res += self.ret("region_free_pro_3", ofs, pre, post)

        # plus global
        sig = self.asm('cmp r1, #0x4b')
        ofs = FindPattern(self.data, sig, start=ofs) + len(sig)
        pre = self.data[ofs:ofs+2]
        post = b'\xf1\xd0'
        res += self.ret("region_free_plus_0", ofs, pre, post)

        sig = self.asm('cmp r1, #0x4a')
        ofs = FindPattern(self.data, sig, start=ofs) + len(sig)
        pre = self.data[ofs:ofs+2]
        post = b'\xdf\xd0'
        res += self.ret("region_free_plus_1", ofs, pre, post)

        sig = self.asm('cmp r1, #0x48')
        ofs = FindPattern(self.data, sig, start=ofs) + len(sig)
        pre = self.data[ofs:ofs+2]
        post = b'\xcd\xd0'
        res += self.ret("region_free_plus_2", ofs, pre, post)

        sig = self.asm('cmp r1, #0x47')
        ofs = FindPattern(self.data, sig, start=ofs) + len(sig)
        ofs = FindPattern(self.data, sig, start=ofs) + len(sig)
        pre = self.data[ofs:ofs+2]
        post = b'\xbc\xd0'
        res += self.ret("region_free_plus_3", ofs, pre, post)

        # normal
        sig = self.asm('cmp r1, #0x58')
        ofs = FindPattern(self.data, sig, start=ofs) + len(sig)
        ofs = FindPattern(self.data, sig, start=ofs) + len(sig)
        pre = self.data[ofs:ofs+2]
        post = b'\x00\xe0'
        res += self.ret("region_free_-1", ofs, pre, post)

        sig = self.asm('cmp r1, #0x45')
        ofs = FindPattern(self.data, sig, start=ofs) + len(sig)
        pre = self.data[ofs:ofs+2]
        post = b'\xee\xd0'
        res += self.ret("region_free_0", ofs, pre, post)

        sig = self.asm('cmp r1, #0x44')
        ofs = FindPattern(self.data, sig, start=ofs) + len(sig)
        pre = self.data[ofs:ofs+2]
        post = b'\xdc\xd0'
        res += self.ret("region_free_1", ofs, pre, post)

        sig = self.asm('cmp r1, #0x43')
        ofs = FindPattern(self.data, sig, start=ofs) + len(sig)
        pre = self.data[ofs:ofs+2]
        post = b'\xca\xd0'
        res += self.ret("region_free_2", ofs, pre, post)

        sig = self.asm('cmp r0, #0x42')
        ofs = FindPattern(self.data, sig, start=ofs) + len(sig)
        pre = self.data[ofs:ofs+2]
        post = b'\xb9\xd0'
        res += self.ret("region_free_3a", ofs, pre, post)
        ofs += 4
        pre = self.data[ofs:ofs+2]
        post = b'\xb7\xd0'
        res += self.ret("region_free_3b", ofs, pre, post)

        return res