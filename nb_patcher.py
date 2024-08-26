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
from util import FindPattern, SignatureException


class NbPatcher(BasePatcher):
    def __init__(self, data, model):
        super().__init__(data, model)

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
        sig = [0x40, 0x1c, 0x10, 0x28, None, 0xdb, 0x00, 0x20, None, 0x4b]
        ofs = FindPattern(self.data, sig) + 6

        sig = [0xf2, 0xdb, 0x0c, 0xb9, 0x86, 0xf8, 0x05]
        ofs_dst = FindPattern(self.data, sig, start=ofs) + 2

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
        '''
        OP: Turbojeet
        Description: Set global region
        '''
        sig = self.asm('cmp r0, #0x4e')
        ofs = FindPattern(self.data, sig, start=0x8000) + len(sig)

        if self.model == "f2pro":
            sig = self.asm('strb.w r4,[r7,#0x4f]')
            ofs_dst = FindPattern(self.data, sig, start=0x8000)
        elif self.model == "f2plus":
            sig = self.asm('strb.w r4,[r7,#0x59]')
            ofs_dst = FindPattern(self.data, sig, start=0x8000)
        elif self.model == "f2":
            sig = self.asm('strb.w r4,[r7,#0x61]')
            ofs_dst = FindPattern(self.data, sig, start=0x8000)

        pre = self.data[ofs:ofs+2]
        post = self.asm(f'b #{ofs_dst-ofs}')
        self.data[ofs:ofs+2] = post

        return self.ret("region_free", ofs, pre, post)

    def kers_multi(self, l0=6, l1=12, l2=20):
        '''
        Creator/Author: Turbojeet
        Description: Set multiplier values for KERS
        '''
        ret = []

        asm = f"""
        movs  r2, #{l0}
        b  MULT
        nop.w
        nop.w
        nop
        movs  r2, #{l1}
        b MULT
        nop.w
        nop.w
        nop
        movs  r2, #{l2}
        nop
        MULT:
        muls  r0, r0, r2
        lsrs  r0, r0, #0xb
        strh.w  r0, [r10, #0x38]
        """
        sig = [0x00, 0xeb, 0x40, 0x00, 0xc0, 0xf3, 0x94, 0x20, 0xaa, 0xf8, 0x38, 0x00, 0x0c, 0xe0, 0x00, 0xeb, 0x40, 0x00, 0xc0, 0xf3, 0x54, 0x20, 0xaa, 0xf8, 0x38, 0x00, 0x05, 0xe0, 0x00, 0xeb, 0x80, 0x00, 0xc0, 0xf3, 0x54, 0x20, 0xaa, 0xf8, 0x38, 0x00]
        ofs = FindPattern(self.data, sig)

        pre = self.data[ofs:ofs+len(sig)]
        post = bytes(self.ks.asm(asm)[0])
        assert len(post) == len(pre), f"{len(post)}, {len(pre)}"
        self.data[ofs:ofs+len(post)] = post
        ret.append(["kers_multi", hex(ofs), pre.hex(), post.hex()])

        return ret
    
    def speed_params(self, max_sport=25, max_drive=20, max_eco=15, max_ped=5):
        '''
        OP: Turbojeet
        Description: Set speed parameters, sport and ped limits work best with region free
        '''
        ret = []

        sig = [0x19, 0x48, 0x90, 0xf8, 0x4f, 0x00, 0x17, 0x4f, 0x1c, 0x4a, 0x1c, 0x4b]
        ofs = FindPattern(self.data, sig) + len(sig)
        pre = self.data[ofs:ofs+2]
        post = self.asm(f'movs r1, #{max_ped}')
        self.data[ofs:ofs+len(post)] = post
        assert len(post) == len(pre), f"{len(post)}, {len(pre)}"
        ret.append([f"speed_params_ped", hex(ofs), pre.hex(), post.hex()])

        offsets = [0x4, 0xc]
        registers = ["r11", "r8"]
        for i in range(2):
            ofs += offsets[i]
            pre = self.data[ofs:ofs+4]
            post = self.asm(f'mov.w {registers[i]}, #{max_drive}')
            self.data[ofs:ofs+len(post)] = post
            assert len(post) == len(pre), f"{len(post)}, {len(pre)}"
            ret.append([f"speed_params_drive_{i}", hex(ofs), pre.hex(), post.hex()])


        sig = [0x0f, 0x20, 0xb8, 0x70, 0x87, 0xf8, 0x03, 0xb0]
        for i in range(10):
            try:
                ofs = FindPattern(self.data, sig, start=ofs+1)
            except SignatureException:
                break

            pre = self.data[ofs:ofs+2]
            post = self.asm(f'movs r0, #{max_eco}')
            self.data[ofs:ofs+len(post)] = post
            assert len(post) == len(pre), f"{len(post)}, {len(pre)}"
            ret.append([f"speed_params_eco_{i}", hex(ofs), pre.hex(), post.hex()])
            
            ofs += len(sig)
            pre = self.data[ofs:ofs+2]
            post = bytearray(self.asm(f'movs r0, #{max_sport}'))
            post[-1] = pre[-1]  # copy over register
            self.data[ofs:ofs+len(post)] = post
            assert len(post) == len(pre), f"{len(post)}, {len(pre)}"
            ret.append([f"speed_params_sport_{i}", hex(ofs), pre.hex(), post.hex()])

        return ret


#    def region_free(self):
#        res = []
#
#        # 1.4.15
#        sig = self.asm('cmp r1, #0x56')
#        ofs = FindPattern(self.data, sig) + len(sig)
#        pre = self.data[ofs:ofs+2]
#        post = b'\xf0\xd0'  # beq -> global
#        res += self.ret("region_free_pro_0", ofs, pre, post)
#
#        sig = self.asm('cmp r1, #0x55')
#        ofs = FindPattern(self.data, sig, start=ofs) + len(sig)
#        pre = self.data[ofs:ofs+2]
#        post = b'\xdd\xd0'
#        res += self.ret("region_free_pro_1", ofs, pre, post)
#
#        sig = self.asm('cmp r1, #0x54')
#        ofs = FindPattern(self.data, sig, start=ofs) + len(sig)
#        pre = self.data[ofs:ofs+2]
#        post = b'\xca\xd0'
#        res += self.ret("region_free_pro_2", ofs, pre, post)
#
#        sig = self.asm('cmp r1, #0x53')
#        ofs = FindPattern(self.data, sig, start=ofs) + len(sig)
#        pre = self.data[ofs:ofs+2]
#        post = b'\xb8\xd0'
#        res += self.ret("region_free_pro_3", ofs, pre, post)
#
#        # plus global
#        sig = self.asm('cmp r1, #0x4b')
#        ofs = FindPattern(self.data, sig, start=ofs) + len(sig)
#        pre = self.data[ofs:ofs+2]
#        post = b'\xf1\xd0'
#        res += self.ret("region_free_plus_0", ofs, pre, post)
#
#        sig = self.asm('cmp r1, #0x4a')
#        ofs = FindPattern(self.data, sig, start=ofs) + len(sig)
#        pre = self.data[ofs:ofs+2]
#        post = b'\xdf\xd0'
#        res += self.ret("region_free_plus_1", ofs, pre, post)
#
#        sig = self.asm('cmp r1, #0x48')
#        ofs = FindPattern(self.data, sig, start=ofs) + len(sig)
#        pre = self.data[ofs:ofs+2]
#        post = b'\xcd\xd0'
#        res += self.ret("region_free_plus_2", ofs, pre, post)
#
#        sig = self.asm('cmp r1, #0x47')
#        ofs = FindPattern(self.data, sig, start=ofs) + len(sig)
#        ofs = FindPattern(self.data, sig, start=ofs) + len(sig)
#        pre = self.data[ofs:ofs+2]
#        post = b'\xbc\xd0'
#        res += self.ret("region_free_plus_3", ofs, pre, post)
#
#        # normal
#        sig = self.asm('cmp r1, #0x58')
#        ofs = FindPattern(self.data, sig, start=ofs) + len(sig)
#        ofs = FindPattern(self.data, sig, start=ofs) + len(sig)
#        pre = self.data[ofs:ofs+2]
#        post = b'\x00\xe0'
#        res += self.ret("region_free_-1", ofs, pre, post)
#
#        sig = self.asm('cmp r1, #0x45')
#        ofs = FindPattern(self.data, sig, start=ofs) + len(sig)
#        pre = self.data[ofs:ofs+2]
#        post = b'\xee\xd0'
#        res += self.ret("region_free_0", ofs, pre, post)
#
#        sig = self.asm('cmp r1, #0x44')
#        ofs = FindPattern(self.data, sig, start=ofs) + len(sig)
#        pre = self.data[ofs:ofs+2]
#        post = b'\xdc\xd0'
#        res += self.ret("region_free_1", ofs, pre, post)
#
#        sig = self.asm('cmp r1, #0x43')
#        ofs = FindPattern(self.data, sig, start=ofs) + len(sig)
#        pre = self.data[ofs:ofs+2]
#        post = b'\xca\xd0'
#        res += self.ret("region_free_2", ofs, pre, post)
#
#        sig = self.asm('cmp r0, #0x42')
#        ofs = FindPattern(self.data, sig, start=ofs) + len(sig)
#        pre = self.data[ofs:ofs+2]
#        post = b'\xb9\xd0'
#        res += self.ret("region_free_3a", ofs, pre, post)
#        ofs += 4
#        pre = self.data[ofs:ofs+2]
#        post = b'\xb7\xd0'
#        res += self.ret("region_free_3b", ofs, pre, post)
#
#        return res