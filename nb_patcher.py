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
        Description: Disables error 40/41, which is thrown when motor NTC is missing
        '''
        sig = [ 0xf6, 0xf7, None, 0xf9, 0xf6, 0xf7, None, 0xfa ]

        ofs = FindPattern(self.data, sig)
        pre = self.data[ofs:ofs+8]
        post = self.asm('nop.w\nnop.w')
        self.data[ofs:ofs+8] = post
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
        res = []

        if self.model == "g2":
            sig = [ 0x18, 0x78, 0xff, 0x21, 0x03, 0x24, 0x30, 0x28, 0x05, 0xd1 ]
            ofs = FindPattern(self.data, sig) + len(sig) - 2
            
            sig = [ 0x33, 0x48, 0x5c, 0x30, 0xfc, 0xf7, 0xbe, 0xfe ]
            ofs_dst = FindPattern(self.data, sig, start=ofs)

            pre = self.data[ofs:ofs+2]
            post = self.asm(f"b #{ofs_dst-ofs}")
            self.data[ofs:ofs+2] = post
            res += self.ret("region_free", ofs, pre, post)
        elif self.model in ["4max", "4plus"]:
            sig = [ 0x34, 0x2b, 0x0e, 0xd1, 0x90, 0xf8, 0x01, 0xc0 ]
            ofs = FindPattern(self.data, sig) + 2
            pre = self.data[ofs:ofs+2]
            
            sig = [ 0x04, 0x20, 0x87, 0xf8, 0x42, 0x00, 0x95, 0xe0 ]
            ofs_dst = FindPattern(self.data, sig, start=ofs)
            post = self.asm(f"b #{ofs_dst-ofs}")
            self.data[ofs:ofs+2] = post
            res += self.ret("region_free_0", ofs, pre, post)

            if self.model == "4max":
                pre = self.data[ofs_dst:ofs_dst+2]
                post = self.asm("movs r0, #0x6")
                self.data[ofs_dst:ofs_dst+2] = post
                res += self.ret("region_free_1", ofs_dst, pre, post)
        else:
            sig = self.asm('cmp r0, #0x4e')
            ofs = FindPattern(self.data, sig, start=0x8000) + len(sig)
            if self.model == "f2pro":
                sig = self.asm('strb.w r4,[r7,#0x4f]')
            elif self.model == "f2plus":
                sig = self.asm('strb.w r4,[r7,#0x59]')
            elif self.model == "f2":
                sig = self.asm('strb.w r4,[r7,#0x61]')
            ofs_dst = FindPattern(self.data, sig, start=0x8000)

            pre = self.data[ofs:ofs+2]
            post = self.asm(f'b #{ofs_dst-ofs}')
            self.data[ofs:ofs+2] = post
            res += self.ret("region_free", ofs, pre, post)

        return res

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
    
    def speed_params(self, max_sport=25, max_drive=20, max_eco=15, max_ped=10):
        '''
        OP: Turbojeet
        Description: Set speed parameters, sport and ped limits work best with region free
        '''
        ret = []

        if self.model == "g2":
            sig = [ 0xa9, 0x4f, 0xdf, 0xf8, 0xa8, 0x92 ]
            ofs = FindPattern(self.data, sig) + len(sig) + 2 * 4
            pre = self.data[ofs:ofs+4]
            post = self.asm(f'mov.w r10, #{max_drive}')
            self.data[ofs:ofs+len(post)] = post
            assert len(post) == len(pre), f"{len(post)}, {len(pre)}"
            ret.append([f"speed_params_drive", hex(ofs), pre.hex(), post.hex()])

            sig = [ 0x10, 0x21, 0x81, 0x72, 0x80, 0xf8, 0x0b, 0xa0 ]
            ofs = FindPattern(self.data, sig)
            pre = self.data[ofs:ofs+2]
            post = self.asm(f'movs r1, #{max_eco}')
            self.data[ofs:ofs+len(post)] = post
            assert len(post) == len(pre), f"{len(post)}, {len(pre)}"
            ret.append([f"speed_params_eco", hex(ofs), pre.hex(), post.hex()])

            ofs += len(sig)
            pre = self.data[ofs:ofs+2]
            post = self.asm(f'movs r1, #{max_sport}')
            self.data[ofs:ofs+len(post)] = post
            assert len(post) == len(pre), f"{len(post)}, {len(pre)}"
            ret.append([f"speed_params_sport", hex(ofs), pre.hex(), post.hex()])

            # G2 has fancy additional checks
            sig = [ 0xdf, 0xf8, 0x14, 0xa1, 0x45, 0x4b, 0x4f, 0xf0, 0x32, 0x09 ]
            ofs = FindPattern(self.data, sig)
            sig = [ 0x58, 0x49, 0x08, 0x68, 0x43, 0xf6, 0x58, 0x62 ]
            ofs_dst = FindPattern(self.data, sig)
            pre = self.data[ofs:ofs+6]
            post = self.asm(f'''ldrb       r0,[r3,#0xc]
                                strh       r0,[r4,#0x26]
                                b          #{ofs_dst-ofs}''')
            self.data[ofs:ofs+len(post)] = post
            assert len(post) == len(pre), f"{len(post)}, {len(pre)}"
            ret.append([f"speed_params_fix1", hex(ofs), pre.hex(), post.hex()])

            sig = [ 0x08, 0xd0, 0xa2, 0xf8, 0xc8, 0x00 ]
            ofs = FindPattern(self.data, sig)
            pre = self.data[ofs:ofs+2]
            post = self.asm('nop')
            self.data[ofs:ofs+len(post)] = post
            assert len(post) == len(pre), f"{len(post)}, {len(pre)}"
            ret.append([f"speed_params_fix2", hex(ofs), pre.hex(), post.hex()])
        elif self.model in ["4max", "4plus"]:
            sig = [ 0x87, 0xf8, 0x43, 0x50, 0x03, 0x78, 0xff, 0x24 ]
            ofs = FindPattern(self.data, sig) + len(sig)
            pre = self.data[ofs:ofs+2]
            post = self.asm(f'movs r2, #{max_ped}')
            self.data[ofs:ofs+len(post)] = post
            assert len(post) == len(pre), f"{len(post)}, {len(pre)}"
            ret.append([f"speed_params_ped", hex(ofs), pre.hex(), post.hex()])

            sig = [ 0x87, 0xf8, 0x42, 0x40, 0x27, 0x48, 0x90, 0xf8, 0x42, 0xb0 ]
            ofs = FindPattern(self.data, sig) + len(sig)
            pre = self.data[ofs:ofs+2]
            post = self.asm(f'movs r4, #{max_drive}')
            self.data[ofs:ofs+len(post)] = post
            assert len(post) == len(pre), f"{len(post)}, {len(pre)}"
            ret.append([f"speed_params_drive", hex(ofs), pre.hex(), post.hex()])

            ofs += 12
            pre = self.data[ofs:ofs+4]
            post = self.asm(f'movw r10, #{max_sport}')
            self.data[ofs:ofs+len(post)] = post
            assert len(post) == len(pre), f"{len(post)}, {len(pre)}"
            ret.append([f"speed_params_sport", hex(ofs), pre.hex(), post.hex()])
        else:
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

    def dpc(self):
        res = []

        if self.model == "g2":
            sig = [ 0x90, 0xfb, 0xf2, 0xf0, 0x09, 0x68 ]
            ofs = FindPattern(self.data, sig) - 2
            pre = self.data[ofs:ofs+2]
            post = self.asm('b #0x6')
            self.data[ofs:ofs+2] = post
            return self.ret("dpc", ofs, pre, post)

        sig = [0xaa, 0xf8, 0xec, 0x60, 0x42, 0x46]
        ofs = FindPattern(self.data, sig)

        pre = self.data[ofs:ofs+4]
        post = self.asm('nop.w')
        self.data[ofs:ofs+4] = post
        res += self.ret("dpc_nop", ofs, pre, post)

        # temp fix, set to 1 instead of 0
        sig = self.asm('strh.w r5,[r0,#0x40]')
        ofs = FindPattern(self.data, sig, start=ofs)
        pre = self.data[ofs:ofs+4]
        post = self.asm('strh.w r6,[r0,#0x1e]')
        self.data[ofs:ofs+4] = post
        res += self.ret("tmp_dpc_1", ofs, pre, post)

        return res

    def remove_autobrake(self):
        if self.model == "g2":
            sig = [ 0x58, 0x49, 0x08, 0x68, 0x43, 0xf6, 0x58, 0x62, 0x90, 0x42, 0x1a, 0xdd ]
            ofs = FindPattern(self.data, sig) + len(sig) - 2
            pre = self.data[ofs:ofs+2]
            post = pre.copy()
            post[1] = 0xe0
            self.data[ofs:ofs+2] = post
        elif self.model in ["4max", "4plus"]:
            sig = [ 0x38, 0x7b, 0xf8, 0xf7, 0x7f, 0xf8, 0xb0, 0xee, 0x4c, 0x8a ]
            ofs = FindPattern(self.data, sig)

            sig = [ 0x70, 0x6f, 0xb0, 0x67, 0xb9, 0xf9, 0x64, 0x10, 0x05, 0x29, 0x12, 0xdc ]
            ofs_dst = FindPattern(self.data, sig, start=ofs)
            pre = self.data[ofs:ofs+2]
            post = self.asm(f'b #{ofs_dst-ofs}')
            self.data[ofs:ofs+2] = post
        else:
            sig = [ 0x1a, 0x68, 0x90, 0x42, 0x30, 0xda ]
            ofs = FindPattern(self.data, sig) + 4
            
            sig = [ 0x9a, 0xf8, 0x13, 0x00, 0x10, 0xb1, 0x01, 0x28, 0x34, 0xd1, 0x0f, 0xe0 ]
            ofs_dst  = FindPattern(self.data, sig, start=ofs)

            pre = self.data[ofs:ofs+2]
            post = self.asm(f'b #{ofs_dst-ofs}')
            self.data[ofs:ofs+2] = post

        return self.ret("remove_autobrake", ofs, pre, post)
    
    def cc_delay(self, seconds=5):
        res = []

        delay = int(seconds * 200)

        sig = self.asm('mov.w r1, #1000')
        ofs = FindPattern(self.data, sig, start=0x2000)
        pre = self.data[ofs:ofs+4]
        post = self.asm(f'mov.w r1, #{delay}')
        self.data[ofs:ofs+4] = post
        res += self.ret("cc_delay", ofs, pre, post)

        # cc mode = 1, temp fix
        # Todo: Move this into own patch
        try:
            if self.model in ["4max", "4plus"]:
                sig = self.asm('strh.w r6,[r8,#0xee]')
                post = self.asm('strh.w r6,[r8,#0xf8]')
            else:
                sig = self.asm('strh.w r5,[r0,#0x42]')
                post = self.asm('strh.w r6,[r0,#0x112]')

            ofs = FindPattern(self.data, sig, start=ofs)
            pre = self.data[ofs:ofs+4]
            self.data[ofs:ofs+4] = post
            res += self.ret("tmp_cc_mode_1", ofs, pre, post)
        except SignatureException:
            pass

        return res

    def remove_charging_mode(self):
        if self.model in ["g2", "4max", "4plus"]:
            sig = [0x7B, 0x20, 0xB9, None, 0x79, 0x10, 0xB9, None, 0xF8]
            ofs = FindPattern(self.data, sig) - 5
            pre = self.data[ofs:ofs+4]
            post = self.asm("nop.w")
            self.data[ofs:ofs+4] = post
        else:
            sig = [0x78, 0x8A, 0x28, 0xB1, 0x86, 0xF8, 0x38, 0x40]
            ofs = FindPattern(self.data, sig) + 2
            pre = self.data[ofs:ofs+2]
            post = self.asm("nop")
            self.data[ofs:ofs+2] = post
        return [("no_charge", hex(ofs), pre.hex(), post.hex())]

    def remove_kers(self):
        if self.model == "g2":
            sig = [ 0x0f, 0x4a, 0xb2, 0xf8, 0xf6, 0x30, 0x73, 0xb1 ]
            ofs = FindPattern(self.data, sig) + len(sig) - 2

            sig = [ 0x00, 0x20, 0x08, 0x85, 0x70, 0x47 ]
            ofs_dst = FindPattern(self.data, sig, start=ofs)

            pre = self.data[ofs:ofs+2]
            post = self.asm(f"b #{ofs_dst-ofs}")
            self.data[ofs:ofs+2] = post

            return self.ret("remove_kers", ofs, pre, post)

    def ampere_ped(self, amps, force=False):
        return self.ampere_eco(amps, force)

    def ampere_eco(self, amps, force=True):
        reg = 12
        if self.model == "g2":
            sig = [ 0x4f, 0xf4, 0xfa, 0x51, 0x01, 0x2a, 0x10, 0xd0 ]
            ofs = FindPattern(self.data, sig)
            reg = 1
        else:
            sig = [0x19, 0x48, 0x90, 0xf8, 0x4f, 0x00, 0x17, 0x4f, 0x1c, 0x4a, 0x1c, 0x4b]
            ofs = FindPattern(self.data, sig) + len(sig) + 8
        pre = self.data[ofs:ofs+4]
        post = self.asm(f'movw r{reg}, #{amps}')
        self.data[ofs:ofs+4] = post
        return self.ret("ampere_eco", ofs, pre, post)

    def ampere_drive(self, amps, force=True):
        reg = 9
        if self.model == "g2":
            sig = [ 0x44, 0xf2, 0x68, 0x20, 0xa0, 0x67 ]
            ofs = FindPattern(self.data, sig)
            reg = 0
        else:
            sig = [0x19, 0x48, 0x90, 0xf8, 0x4f, 0x00, 0x17, 0x4f, 0x1c, 0x4a, 0x1c, 0x4b]
            ofs = FindPattern(self.data, sig) + len(sig) + 30
        pre = self.data[ofs:ofs+4]
        post = self.asm(f'movw r{reg}, #{amps}')
        self.data[ofs:ofs+4] = post
        return self.ret("ampere_drive", ofs, pre, post)

    def ampere_sport(self, amps, force=True):
        res = []

        if self.model == "g2":
            sig = [ 0xfc, 0xf7, 0x0a, 0xfa, 0x45, 0xf6, 0xb4, 0x71, 0x01, 0x28, 0x0a, 0xd0 ]
            ofs = FindPattern(self.data, sig) + len(sig) - 2
            if force:
                pre = self.data[ofs:ofs+2]
                post = pre.copy()
                post[1] = 0xe0
                self.data[ofs:ofs+2] = post
                res += self.ret("ampere_sport_force", ofs, pre, post)
            ofs -= 6
            pre = self.data[ofs:ofs+4]
            post = self.asm(f'movw r1, #{amps}')
            self.data[ofs:ofs+4] = post
            res += self.ret("ampere_sport", ofs, pre, post)

            return res

        ofs = 0x8000
        for i in range(20):
            sig = [ None, 0x71, 0xc7, 0xf8, 0x10, 0xc0 ]
            try:
                ofs = FindPattern(self.data, sig, start=ofs+1)
                sig = [0xb8, 0x61]
                ofs = FindPattern(self.data, sig, start=ofs+1) - 4
            except SignatureException:
                break

            pre = self.data[ofs:ofs+4]
            post = self.asm(f'movw r0, #{amps}')
            self.data[ofs:ofs+4] = post
            res += self.ret(f"ampere_sport_{i}", ofs, pre, post)


        return res

    def ampere_max_eco(self, amps):
        reg = 0
        if self.model == "g2":
            sig = [ None, 0x49, 0x49, 0x42, 0x41, 0x62 ]
            ofs = FindPattern(self.data, sig) + len(sig)
            reg = 1
        else:
            sig = [ 0x47, 0xf2, 0x30, 0x50, 0x60, 0x61, 0xd1, 0xe0 ]
            ofs = FindPattern(self.data, sig)
        pre = self.data[ofs:ofs+4]
        post = self.asm(f'movw r{reg}, #{amps}')
        self.data[ofs:ofs+4] = post
        return self.ret("ampere_max_eco", ofs, pre, post)

    def ampere_max_drive(self, amps):
        reg = 0
        if self.model == "g2":
            sig = [ 0x8f, 0x49, 0x49, 0x42, 0x41, 0x62 ]
            ofs = FindPattern(self.data, sig) + len(sig) + 6
            reg = 1
        else:
            sig = [ 0x49, 0xf6, 0x40, 0x40, 0x60, 0x61 ]
            ofs = FindPattern(self.data, sig)
        pre = self.data[ofs:ofs+4]
        post = self.asm(f'movw r{reg}, #{amps}')
        self.data[ofs:ofs+4] = post
        return self.ret("ampere_max_drive", ofs, pre, post)

    def ampere_max_sport(self, amps):
        '''
        Description: Set max current for sport mode, requires acceleration mode to be set to 2
        '''
        if self.model == "g2":
            sig = [ 0x80, 0xc7, 0xfe, 0xff, 0x70, 0x11, 0x01, 0x00, 0x18, 0x02, 0xff, 0xff ]
            ofs = FindPattern(self.data, sig)
            post = int.to_bytes((-amps), 4, byteorder='little', signed=True)
        else:
            sig = [ 0x40, 0x19, 0x01, 0x00, 0x80, 0x97, 0x06, 0x00, 0x00, 0xca, 0x08, 0x00 ]
            ofs = FindPattern(self.data, sig)
            post = amps.to_bytes(4, byteorder='little')
        pre = self.data[ofs:ofs+4]
        self.data[ofs:ofs+4] = post
        return self.ret("ampere_max_sport", ofs, pre, post)

    def bms_baudrate(self, val):
        if self.model == "g2":
            raise NotImplementedError("Not supported on G2")

        sig = [ 0x4f, 0xf4, 0xe1, 0x30, 0x03, 0x90, 0x00, 0x21, 0xad, 0xf8, 0x10, 0x10 ]
        ofs = FindPattern(self.data, sig)
        pre = self.data[ofs:ofs+4]
        post = bytes(self.ks.asm('MOV.W R0,#{}'.format(val))[0])
        self.data[ofs:ofs+4] = post

        return self.ret("bms_baudrate", ofs, pre, post)

    def volt_limit(self, volts):
        sig = [0x91, 0x42, 0x04, 0xD3, None, 0x68, 0x41, 0xF2, None, None, 0x88, 0x42, 0x06, 0xD9]
        ofs = FindPattern(self.data, sig) + 6
        pre = self.data[ofs:ofs+4]
        post = bytes(self.ks.asm(f"MOVW R1,#{int(volts*100)}")[0])
        self.data[ofs:ofs+4] = post

        return self.ret("volt_limit", ofs, pre, post)

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