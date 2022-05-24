# VLT Firmware Patcher
# Copyright (C) 2022 Daljeet Nandha
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

# Based on https://github.com/BotoX/xiaomi-m365-firmware-patcher/blob/master/patcher.py

#!/usr/bin/python3
from binascii import hexlify, unhexlify
import struct
import keystone
#import capstone

# https://web.eecs.umich.edu/~prabal/teaching/eecs373-f10/readings/ARMv7-M_ARM.pdf
MOVW_T3_IMM = [*[None]*5, 11, *[None]*6, 15, 14, 13, 12, None, 10, 9, 8, *[None]*4, 7, 6, 5, 4, 3, 2, 1, 0]
MOVS_T1_IMM = [*[None]*8, 7, 6, 5, 4, 3, 2, 1, 0]


def PatchImm(data, ofs, size, imm, signature):
    assert size % 2 == 0, 'size must be power of 2!'
    assert len(signature) == size * 8, 'signature must be exactly size * 8 long!'
    imm = int.from_bytes(imm, 'little')
    sfmt = '<' + 'H' * (size // 2)

    sigs = [signature[i:i + 16][::-1] for i in range(0, len(signature), 16)]
    orig = data[ofs:ofs+size]
    words = struct.unpack(sfmt, orig)

    patched = []
    for i, word in enumerate(words):
        for j in range(16):
            imm_bitofs = sigs[i][j]
            if imm_bitofs is None:
                continue

            imm_mask = 1 << imm_bitofs
            word_mask = 1 << j

            if imm & imm_mask:
                word |= word_mask
            else:
                word &= ~word_mask
        patched.append(word)

    packed = struct.pack(sfmt, *patched)
    data[ofs:ofs+size] = packed
    return (orig, packed)


class SignatureException(Exception):
    pass


def FindPattern(data, signature, mask=None, start=None, maxit=None):
    sig_len = len(signature)
    if start is None:
        start = 0
    stop = len(data) - len(signature)
    if maxit is not None:
        stop = start + maxit

    if mask:
        assert sig_len == len(mask), 'mask must be as long as the signature!'
        for i in range(sig_len):
            signature[i] &= mask[i]

    for i in range(start, stop):
        matches = 0

        while signature[matches] is None or signature[matches] == (data[i + matches] & (mask[matches] if mask else 0xFF)):
            matches += 1
            if matches == sig_len:
                return i

    raise SignatureException('Pattern not found!')


class FirmwarePatcher():
    def __init__(self, data):
        self.data = bytearray(data)
        self.ks = keystone.Ks(keystone.KS_ARCH_ARM, keystone.KS_MODE_THUMB)
        #self.cs = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)

    def error_on_pair(self, errnum=2):
        '''
        First offset of old No Kers Mod ("Error 1" Bug)
        '''
        ret = []

        sig = [0x01, 0x40, 0x0a, 0x20, 0x3c, 0xe0, 0x00, 0x88]
        ofs = FindPattern(self.data, sig) + 2
        pre = self.data[ofs:ofs+2]
        post = bytes(self.ks.asm('movs r0, #{}'.format(errnum))[0])
        self.data[ofs:ofs+2] = post
        ret.append(["eop", hex(ofs), pre.hex(), post.hex()])

        return ret

    def remove_autobrake(self):
        '''
        '''
        sig = [None, 0x68, 0x42, 0xf6, 0x6e, 0x0c]
        ofs = FindPattern(self.data, sig) + 2
        pre = self.data[ofs:ofs+4]
        post = bytes(self.ks.asm('MOVW IP, #0xffff')[0])
        self.data[ofs:ofs+4] = post
        return [("no_autobrake", hex(ofs), pre.hex(), post.hex())]

    def remove_charging_mode(self):
        '''
        '''
        sig = [0xB8, 0xF8, 0x12, 0x00, 0x20, 0xB1, 0x84, 0xF8, 0x3A]
        ofs = FindPattern(self.data, sig) + 4
        pre = self.data[ofs:ofs+2]
        post = bytes(self.ks.asm('NOP')[0])
        self.data[ofs:ofs+2] = post
        return [("no_charge", hex(ofs), pre.hex(), post.hex())]

    def current_raising_coeff(self, coeff):
        '''
        '''
        ret = []

        val = hex(coeff)
        sig = [0x95, 0xf8, 0x34, None, None, 0x21, 0x4f, 0xf4, 0x96, 0x70]
        ofs = FindPattern(self.data, sig) + 6
        pre = self.data[ofs:ofs+4]
        post = bytes(self.ks.asm('MOV.W R0, #{}'.format(val))[0])
        self.data[ofs:ofs+4] = post
        ret.append(["crc", hex(ofs), pre.hex(), post.hex()])

        return ret

    def speed_limit(self, kmh):
        '''
        '''
        ret = []

        val = hex(kmh)

        sig = [0x95, 0xf8, 0x34, None, None, 0x21, 0x4f, 0xf4, 0x96, 0x70]
        ofs = FindPattern(self.data, sig) + 4
        pre = self.data[ofs:ofs+2]
        post = bytes(self.ks.asm('MOVS R1, #{}'.format(val))[0])
        self.data[ofs:ofs+2] = post
        ret.append(["spt_de", hex(ofs), pre.hex(), post.hex()])

        return ret

    def speed_limit_global(self, kmh):
        '''
        '''
        ret = []

        val = hex(kmh)
        try:
            # 216 / 304
            sig = [0x01, 0x2b, 0x01, 0xd0, 0x19, 0x23, 0x09, 0xe0, 0x61, 0x84]
            ofs = FindPattern(self.data, sig) + 4
            pre = self.data[ofs:ofs+2]
            post = bytes(self.ks.asm('MOVS R3, #{}'.format(val))[0])
            self.data[ofs:ofs+2] = post
            ret.append(["spt_us", hex(ofs), pre.hex(), post.hex()])
        except SignatureException:
            # for 319 this moved to the top and 'movs' became 'mov.w'
            sig = [0x95, 0xf8, 0x34, None, None, 0x21, 0x4f, 0xf4, 0x96, 0x70]
            ofs = FindPattern(self.data, sig) + 0xe
            pre = self.data[ofs:ofs+4]
            post = bytes(self.ks.asm('MOV.W R8, #{}'.format(val))[0])
            self.data[ofs:ofs+4] = post
            ret.append(["spt_us", hex(ofs), pre.hex(), post.hex()])

        return ret

    def speed_limit_pedo(self, kmh):
        '''
        '''
        ret = []

        val = hex(kmh)

        sig = [0x4f, 0xf0, 0x05, None, 0x01, None, 0x02, 0xd1]
        ofs = FindPattern(self.data, sig)
        pre = self.data[ofs:ofs+4]
        reg = pre[-1]
        post = bytes(self.ks.asm('MOV.W R{}, #{}'.format(reg, val))[0])
        self.data[ofs:ofs+4] = post
        ret.append(["spt_pedo", hex(ofs), pre.hex(), post.hex()])

        return ret

    def motor_start_speed(self, kmh):
        '''
        '''
        val = struct.pack('<H', round(kmh * 345))
        sig = [0x01, 0x68, 0x40, 0xF2, 0xBD, 0x62]
        ofs = FindPattern(self.data, sig) + 2
        pre, post = PatchImm(self.data, ofs, 4, val, MOVW_T3_IMM)
        return [("mss", hex(ofs), pre.hex(), post.hex())]

    def brakelight_mod(self, no_bl_pedo=False):
        '''
        Stops blinky
        '''
        ret = []

        sig = [0x01, 0x29, None, 0xd0, 0xa1, 0x79, 0x01, 0x29]
        ofs = FindPattern(self.data, sig) + 6
        pre = self.data[ofs:ofs+2]
        post = bytes(self.ks.asm('CMP R1, #0xff')[0])
        self.data[ofs:ofs+2] = post
        ret.append(["blm_throttle", hex(ofs), pre.hex(), post.hex()])

        #sig = [0x01, 0x29, None, 0xd0, 0x90, 0xf8, 0x34, 0x10, 0x01, 0x29]
        #ofs = FindPattern(self.data, sig) + 8
        ofs += 8
        pre = self.data[ofs:ofs+2]
        post = bytes(self.ks.asm('CMP R1, #0xff')[0])
        self.data[ofs:ofs+2] = post
        ret.append(["blm_pedo", hex(ofs), pre.hex(), post.hex()])

        sig = [0x90, 0xf8, None, None, None, 0x28, None, 0xd1]
        ofs = FindPattern(self.data, sig) + 4
        pre = self.data[ofs:ofs+2]
        post = bytes(self.ks.asm('CMP R0, #0xff')[0])
        self.data[ofs:ofs+2] = post
        ret.append(["blm_glob", hex(ofs), pre.hex(), post.hex()])

        if no_bl_pedo:  # no backlight in pedestrian mode (untested)
            sig = [None, 0xb3, 0x90, 0xf8, 0x34, None, 0x01, None, None, 0xd0]
            ofs = FindPattern(self.data, sig) + 6
            pre = self.data[ofs:ofs+2]
            reg = -1
            if pre[-1] == 0x28:
                reg = 0
            elif pre[-1] == 0x29:
                reg = 1
            else:
                raise Exception("invalid firmware file")
            post = bytes(self.ks.asm('CMP R{}, #0xff'.format(reg))[0])
            self.data[ofs:ofs+2] = post
            ret.append(["blm_pedo_bl", hex(ofs), pre.hex(), post.hex()])

        return ret

    def wheel_speed_const(self, factor, def1=345, def2=1387):
        '''
        Bigger wheels need special treatment
        '''
        ret = []

        val1 = struct.pack('<H', round(def1/factor))
        val2 = struct.pack('<H', round(def2*factor))

        sig = [0xB4, 0xF9, None, 0x00, 0x40, 0xF2, 0x59, 0x11, 0x48, 0x43]
        ofs = FindPattern(self.data, sig) + 4
        pre, post = PatchImm(self.data, ofs, 4, val1, MOVW_T3_IMM)
        ret.append(["wheel_speed_const_0", hex(ofs), pre.hex(), post.hex()])

        ofs -= 0x18
        pre = self.data[ofs+2:ofs+4]
        if pre[0] == 0x59 and pre[1] == 0x11:  # not in 247
            pre, post = PatchImm(self.data, ofs, 4, val1, MOVW_T3_IMM)
            ret.append(["wheel_speed_const_1", hex(ofs), pre.hex(), post.hex()])

        sig = [0x60, 0x60, 0x60, 0x68, 0x40, 0xF2, 0x6B, 0x51, 0x48, 0x43]
        ofs = FindPattern(self.data, sig) + 4
        pre, post = PatchImm(self.data, ofs, 4, val2, MOVW_T3_IMM)
        ret.append(["wheel_other_const", hex(ofs), pre.hex(), post.hex()])

        return ret

    def ampere_speed(self, amps, force=True):
        '''
        More current <=> more consumption
        '''
        ret = []

        val = struct.pack('<H', amps)

        sig = [0x13, 0xD2, None, 0x85, None, 0xE0, None, 0x8E]
        ofs = FindPattern(self.data, sig) + 8
        pre = self.data[ofs:ofs+2]
        if pre[0] <= 0x46 and pre[1] >= 0xf2:
            # DRV216 / 304
            pre, post = PatchImm(self.data, ofs, 4, val, MOVW_T3_IMM)
            ret.append(["amp_speed", hex(ofs), pre.hex(), post.hex()])

            if force:
                ofs += 4
                pre = self.data[ofs:ofs+2]
                post = bytes(self.ks.asm('CMP R0, R0')[0])
                self.data[ofs:ofs+2] = post
                ret.append(["amp_speed_nop", hex(ofs), pre.hex(), post.hex()])
        else:
            # DRV319 / 247
            if force:
                post = bytes(self.ks.asm('CMP R0, R0')[0])
                self.data[ofs:ofs+2] = post
                ret.append(["amp_speed_nop", hex(ofs), pre.hex(), post.hex()])

            # moved up to speed limits section
            sig = [None, 0x21, 0x4f, 0xf4, 0x96, 0x70]
            ofs = FindPattern(self.data, sig) + 6
            pre, post = PatchImm(self.data, ofs, 4, val, MOVW_T3_IMM)
            ret.append(["amp_speed", hex(ofs), pre.hex(), post.hex()])

        return ret

    def ampere_pedo(self, amps, amps_max, force=False):
        ret = []

        sig = [None, 0x8e, 0x41, 0xf6, 0x58, None, None, None, 0x01, 0xd2]
        ofs = FindPattern(self.data, sig) + 2
        pre = self.data[ofs:ofs+4]
        reg = 0
        if pre[-1] == 0x32:
            reg = 2
        elif pre[-1] == 0x33:
            reg = 3
        elif pre[-1] == 0x3c:
            reg = 12
        else:
            raise Exception("invalid firmware file")
        post = bytes(self.ks.asm('MOVW R{},#{}'.format(reg, amps))[0])
        self.data[ofs:ofs+4] = post
        ret.append(["amp_pedo", hex(ofs), pre.hex(), post.hex()])

        if force:
            ofs += 4
            pre = self.data[ofs:ofs+2]
            post = bytes(self.ks.asm('CMP R0, R0')[0])
            self.data[ofs:ofs+2] = post
            ret.append(["amp_pedo_nop", hex(ofs), pre.hex(), post.hex()])

        sig = [0xa4, 0xf8, 0x22, None, 0x4f, 0xf4, 0xfa, None, None, 0xe0]
        ofs = FindPattern(self.data, sig) + 4
        pre = self.data[ofs:ofs+4]
        reg = 0
        if pre[-1] == 0x52:
            reg = 2
        elif pre[-1] == 0x53:
            reg = 3
        else:
            raise Exception("invalid firmware file")
        post = bytes(self.ks.asm('MOVW R{},#{}'.format(reg, amps_max))[0])
        self.data[ofs:ofs+4] = post
        ret.append(["amp_pedo_max", hex(ofs), pre.hex(), post.hex()])

        return ret

    def dpc(self):
        '''
        '''
        ret = []
        sig = [0x25, 0x4a, 0x00, 0x21, 0xa1, 0x71, 0xa2, 0xf8, 0xec, 0x10, 0x63, 0x79]
        ofs = FindPattern(self.data, sig) + 6
        pre = self.data[ofs:ofs+2]
        post = bytes(self.ks.asm('NOP')[0])
        self.data[ofs:ofs+2] = post
        ret.append(["dpc_nop", hex(ofs), pre.hex(), post.hex()])

        ofs += 2
        pre = self.data[ofs:ofs+2]
        post = bytes(self.ks.asm('NOP')[0])
        self.data[ofs:ofs+2] = post
        ret.append(["dpc_nop", hex(ofs), pre.hex(), post.hex()])

        sig = [0xa4, 0xf8, 0xe2, None, 0xa4, 0xf8, 0xf0, None, 0xa4, 0xf8, 0xee, None]
        ofs = FindPattern(self.data, sig) + 4
        pre = self.data[ofs:ofs+4]
        reg = 0
        if pre[-1] == 0x70:
            reg = 7  # DRV236 / 319
        elif pre[-1] == 0x60:
            reg = 6  # DRV304
        else:
            raise Exception("invalid firmware file")
        post = bytes(self.ks.asm('STRH.W R{}, [R4, #0xEC]'.format(reg))[0])
        self.data[ofs:ofs+4] = post
        ret.append(["dpc_reset", hex(ofs), pre.hex(), post.hex()])

        return ret

    def shutdown_time(self, seconds):
        '''
        '''
        delay = int(seconds * 200)
        assert delay.bit_length() <= 12, 'bit length overflow'
        sig = [0x0a, 0x60, 0xb0, 0xf5, 0xfa, 0x7f, 0x08, 0xd9]
        ofs = FindPattern(self.data, sig) + 2
        pre = self.data[ofs:ofs+4]
        post = bytes(self.ks.asm('CMP.W R0, #{:n}'.format(delay))[0])
        self.data[ofs:ofs+4] = post
        return [("shutdown", hex(ofs), pre.hex(), post.hex())]

    def ltgm(self):
        '''
        Brute-force address replacement
        '''
        ret = []
        for reg_src in range(6):
            while True:
                try:
                    sig = self.ks.asm('LDRB.W R0,[R{},#0x43]'.format(reg_src))[0]
                    sig[-1] = None  # blank out dst register
                    ofs = FindPattern(self.data, sig)
                    pre = self.data[ofs:ofs+4]
                    reg_dst = pre[-1]>>4
                    post = bytes(self.ks.asm('LDRH.W R{},[R{},#0x13a]'.format(reg_dst, reg_src))[0])
                    self.data[ofs:ofs+4] = post
                    ret.append(["ltgm_read", hex(ofs), pre.hex(), post.hex()])
                except SignatureException:
                    break

        for reg_src in range(6):
            while True:
                try:
                    sig = self.ks.asm('STRB.W R0,[R{},#0x43]'.format(reg_src))[0]
                    sig[-1] = None  # blank out dst register
                    ofs = FindPattern(self.data, sig)
                    pre = self.data[ofs:ofs+4]
                    reg_dst = pre[-1]>>4
                    post = bytes(self.ks.asm('STRH.W R{},[R{},#0x13a]'.format(reg_dst, reg_src))[0])
                    self.data[ofs:ofs+4] = post
                    ret.append(["ltgm_write", hex(ofs), pre.hex(), post.hex()])
                except SignatureException:
                    break

        if not len(ret) in [11, 12]:
            raise SignatureException('Pattern not found')

        return ret

    def reset_mode(self, reset_lgtm=True, reset_dpc=False):
        '''
        Reset register flag when toggling speed -> eco
        '''
        ret = []
        sig = [0x01, 0x29, 0x07, 0xd0, 0x02, 0x29, 0x10, 0xd1, 0x0a, 0xe0]
        ofs = FindPattern(self.data, sig) + 4
        pre = self.data[ofs:ofs+4]
        if reset_lgtm:
            post = bytes(self.ks.asm('STRH.W R6,[R5,#0x13a]')[0])
        elif reset_dpc:
            #post = bytes(self.ks.asm('STRH.W R6,[R5,#0x132]')[0])
            post = bytes(self.ks.asm('NOP')[0])
        else:
            post = bytes(self.ks.asm('NOP')[0])
        self.data[ofs:ofs+4] = post
        ret.append(["ltgm-1", hex(ofs), pre.hex(), post.hex()])

        return ret

    def relight_mod(self, throttle_pos=0x9c, brake_pos=0x3c, reset=False, gm=False, dpc=False, beep=False, delay=False, autolight=False):
        '''
        Set / Reset with Throttle + Brake
        '''
        ret = []

        addr_table = {
            # ofs: [beep,  bcs,  ldr,  thrtl]
            0x666: [0x332, 0x3c, 0x78, 0x274],  # 321
            0x662: [0x332, 0x3c, 0x78, 0x274],  # 319
            0x6e2: [0x332, 0x3c, 0x78, 0x278],  # 248
            0x6de: [0x332, 0x3c, 0x78, 0x278],  # 247
            0x732: [0x39e, 0x34, 0x80, 0x278],  # 304
            0x73a: [0x38e, 0x3c, 0x78, 0x278],  # 236
        }
        dofs = 0x1a

        sig = [0x90, 0xf8, None, None, None, 0x28, None, 0xd1]
        ofs = FindPattern(self.data, sig)

        # smash stuff
        pre = self.data[ofs:ofs+54]
        post = bytes(self.ks.asm('NOP')[0] * 25
                     + self.ks.asm('POP.W {R4, R5, R6, PC}')[0])
        assert len(post) == 54, len(post)
        self.data[ofs:ofs+54] = post

        # and fill it with live
        asm = ""
        if delay:
            asm += """
            ldrb       r6,[r4,#0x18]
            adds       r6,r6,#0x1
            strb       r6,[r4,#0x18]
            cmp        r6,#0xc8
            bls        #0x1a
            strb       r5,[r4,#0x18]
            """

        asm += "adds r1,r0,#0x132\n"
        asm += "movs r0,#0x1\n"
        if gm:
            asm += "strh r{}, [r1, #8]\n".format(0 if reset else 5)
        if dpc:
            asm += "strh r{}, [r1, #0]\n".format(5 if reset else 0)
        addr_f = addr_table[ofs][0]
        if beep:
            asm += f"bl #{addr_f}\n"

        post = bytes(self.ks.asm(asm)[0])
        self.data[ofs:ofs+len(post)] = post

        if autolight:
            if ofs < 0x700:
                # new drvs
                asm = """
                adds       r5,r4,#0xc8
                ldrh       r1,[r5,#0]
                mov.w      r6,#0x40000000
                strh       r1,[r6,#0x34]
                adds       r1,#0x10
                strh       r1,[r5,#0]
                cmp        r1,#0x60
                ble        #0x18
                movs       r1,#0x60
                strh       r1,[r5,#0]
                """
            else:
                asm = """
                movw       r1,#15000
                mov.w      r6,#0x40000000
                strh       r1,[r6,#0x34]
                """

            post = bytes(self.ks.asm(asm)[0])
            self.data[ofs+dofs:ofs+dofs+len(post)] = post

        ret.append(["rl_payload", hex(ofs), pre.hex(), self.data[ofs:ofs+54].hex()])

        addr_b, addr_l, addr_t = addr_table[ofs][1:4]
        # main mod
        asm = f"""
        LDR     R6, {addr_l}
        LDRB.W  R1, [R6, #{addr_t+1}]
        CMP     R1, #{brake_pos}
        BCC     0x14
        LDRB.W  R1, [R6, #{addr_t}]
        CMP     R1, #{throttle_pos}
        BCS     {addr_b}
        B       {addr_b+dofs}
        """
        sig = [None, 0x4c, 0x00, 0x25, 0x61, 0x79, 0x01, 0x29, None, 0xd0]
        ofs = FindPattern(self.data, sig) + 4
        pre = self.data[ofs:ofs+20]
        post = bytes(self.ks.asm(asm)[0])
        assert len(post) == 20, len(post)
        self.data[ofs:ofs+20] = post
        ret.append(["rl_hook", hex(ofs), pre.hex(), post.hex()])

        return ret

    def lower_light(self):
        '''
        Lowers light intensity
        '''
        ret = []

        try:
            sig = [0x4f, 0xf0, 0x80, 0x40, 0x04, 0xf0, None, 0xfc, 0x20, 0x88]
            ofs = FindPattern(self.data, sig) + 0xa
            pre = self.data[ofs:ofs+2]
            post = bytes(self.ks.asm("adds r0,#1")[0])
            self.data[ofs:ofs+2] = post
            ret.append(["lower_light_step", hex(ofs), pre.hex(), post.hex()])

            ofs += 6
            pre = self.data[ofs:ofs+2]
            post = bytes(self.ks.asm("cmp r0,#5")[0])
            self.data[ofs:ofs+2] = post
            ret.append(["lower_light_cmp", hex(ofs), pre.hex(), post.hex()])

            ofs += 4
            pre = self.data[ofs:ofs+2]
            post = bytes(self.ks.asm("movs r0,#5")[0])
            self.data[ofs:ofs+2] = post
            ret.append(["lower_light_max", hex(ofs), pre.hex(), post.hex()])
        except SignatureException:
            # 304 / 236
            asm = """
            movw r1,#5000
            mov.w r0,#0x40000000
            strh r1,[r0,#0x34]
            bx lr
            """
            sig = [0x42, 0xf2, 0x10, 0x71, 0x88, 0x06, 0x04, 0xf0, None, 0xbd]
            ofs = FindPattern(self.data, sig)
            pre = self.data[ofs:ofs+12]
            post = bytes(self.ks.asm(asm)[0])
            self.data[ofs:ofs+12] = post
            ret.append(["lower_light", hex(ofs), pre.hex(), post.hex()])

        return ret

    def amp_meter(self, real=True, shift=8):
        '''
        Replace dashboard battery bars with amp meter
        '''
        ret = []

        if real:
            asm = """
            ldr r1,[pc,#{}]
            ldr r0,[r{},#{}]
            asrs r0,r0,#{}
            bmi #0xc
            """
            addr_table = {
                #pre[0] ofs1 reg ofs2
                0x80: [0xa0, 0, -0x30],  # 247
                0xa8: [0x9c, 5, -0x10],  # 319
            }
        else:
            # set point
            asm = """
            ldr r1,[pc,#{}]
            ldr.w r0,[r1,#{}]
            asrs r0,r0,#{}
            bmi #0xc
            """
            addr_table = {
                #pre[0] ofs1 ofs2
                0x80: [0xa0, 0x20c],  # 247
                0xa8: [0x9c, 0x208],  # 319
            }

        sig = [None, 0x79, 0x27, 0x49, 0x10, 0xb9, 0xfd, 0xf7, None, None, 0x48, 0x70]
        ofs = FindPattern(self.data, sig)
        pre = self.data[ofs:ofs+0xa]
        post = bytes(self.ks.asm(asm.format(*addr_table[pre[0]], shift))[0])
        self.data[ofs:ofs+0xa] = post
        ret.append(["amp_meter", hex(ofs), pre.hex(), post.hex()])

        return ret

    def speedlimit_mod(self):
        '''
        WIP: NEED FIXING

        Allow setting drive and speed mode speed limits by register
        '''
        ret = []

        sig = [0x00, 0xe0, 0xe3, 0x85, 0x95, 0xf8, 0x43, 0x30]
        ofs = FindPattern(self.data, sig) + 4
        pre = self.data[ofs:ofs+4]
        post = bytes(self.ks.asm('LDRH.W R1,[R9,#0xE4]')[0])
        self.data[ofs:ofs+4] = post
        ret.append(["sl_speed", hex(ofs), pre.hex(), post.hex()])
        ofs += 8
        pre = self.data[ofs:ofs+2]
        post = bytes(self.ks.asm('CMP R0, R0')[0])
        self.data[ofs:ofs+2] = post
        ret.append(["sl_speed_cmp", hex(ofs), pre.hex(), post.hex()])

        sig = [0x08, 0xe0, 0xe3, 0x85, 0x95, 0xf8, 0x43, 0x30]
        ofs = FindPattern(self.data, sig) + 4
        pre = self.data[ofs:ofs+4]
        post = bytes(self.ks.asm('LDRH.W R1,[R9,#0xE6]')[0])
        self.data[ofs:ofs+4] = post
        ret.append(["sl_drive", hex(ofs), pre.hex(), post.hex()])
        ofs += 8
        pre = self.data[ofs:ofs+2]
        post = bytes(self.ks.asm('CMP R0, R0')[0])
        self.data[ofs:ofs+2] = post
        ret.append(["sl_drive_cmp", hex(ofs), pre.hex(), post.hex()])

        sig = [0xe2, 0x65, 0x60, 0x85, 0xa8, 0x7f, 0x20, 0xb1]
        ofs = FindPattern(self.data, sig) + 4
        pre = self.data[ofs:ofs+2]
        post = bytes(self.ks.asm('CMP R1,#0x0')[0])
        self.data[ofs:ofs+2] = post
        ret.append(["sl_reset_cmp", hex(ofs), pre.hex(), post.hex()])
        ofs += 2
        pre = self.data[ofs:ofs+2]
        post = bytes(self.ks.asm('BNE #0xc')[0])
        self.data[ofs:ofs+2] = post
        ret.append(["sl_reset_bne", hex(ofs), pre.hex(), post.hex()])
        ofs += 2
        pre = self.data[ofs:ofs+4]
        post = bytes(self.ks.asm('STRH.W R3,[R9,#0xE4]')[0])
        self.data[ofs:ofs+4] = post
        ret.append(["sl_reset_speed", hex(ofs), pre.hex(), post.hex()])
        ofs += 4
        pre = self.data[ofs:ofs+4]
        post = bytes(self.ks.asm('STRH.W R3,[R9,#0xE6]')[0])
        self.data[ofs:ofs+4] = post
        ret.append(["sl_reset_drive", hex(ofs), pre.hex(), post.hex()])
        ofs += 4
        pre = self.data[ofs:ofs+2]
        post = bytes(self.ks.asm('STRH R3, [R4,#0x22]')[0])
        self.data[ofs:ofs+2] = post
        ret.append(["sl_reset_def", hex(ofs), pre.hex(), post.hex()])

        return ret

    def rf_de_brake(self):
        '''
        '''
        ret = []

        sig = bytes.fromhex("52b12b4ab2f86020")
        ofs = FindPattern(self.data, sig)
        pre = self.data[ofs:ofs+2]
        post = bytes(self.ks.asm('NOP')[0])
        self.data[ofs:ofs+2] = post
        ret.append(["rf_de_brake", hex(ofs), pre.hex(), post.hex()])

        return ret

    def rf_bl_unlock(self):
        '''
        '''
        ret = []

        sig = [0x90, 0xf8, 0x43, 0x10, None, 0xb3, 0x90, 0xf8]
        ofs = FindPattern(self.data, sig) + 4
        pre = self.data[ofs:ofs+2]
        addr = 0
        if pre[0] == 0x19:
            addr = 0x4a
        elif pre[0] == 0x39:
            addr = 0x52
        else:
            raise Exception("invalid firmware file")
        post = bytes(self.ks.asm('b #{}'.format(addr))[0])
        self.data[ofs:ofs+2] = post
        ret.append(["rf_bl_unlock", hex(ofs), pre.hex(), post.hex()])

        return ret

    def rf_cc_unlock(self):
        '''
        '''
        ret = []

        sig = bytes.fromhex("1748 90f8 4300 58b9")
        ofs = FindPattern(self.data, sig) + 6
        pre = self.data[ofs:ofs+2]
        post = bytes(self.ks.asm('NOP')[0])
        self.data[ofs:ofs+2] = post
        ret.append(["rf_cc_unlock", hex(ofs), pre.hex(), post.hex()])

        return ret

    def cc_delay(self, seconds):
        '''
        '''
        ret = []

        delay = int(seconds * 200)

        sig = [0xb0, 0xf8, 0xf8, 0x10, None, 0x4b, 0x4f, 0xf4, 0x7a, 0x70]
        ofs = FindPattern(self.data, sig) + 6
        pre = self.data[ofs:ofs+4]
        post = bytes(self.ks.asm('MOV.W R0,#{}'.format(delay))[0])
        self.data[ofs:ofs+4] = post
        ret.append(["cc_delay", hex(ofs), pre.hex(), post.hex()])

        return ret

    def dkc(self, l0=6, l1=12, l2=20):
        '''
        Author: VoodooShamane
        '''
        ret = []

        asm = f"""
        nop
        nop
        nop
        nop
        cmp	r2, #0
        ble	#0x1e
        cmp	r2, #1
        beq	#0x22
        cmp	r2, #2
        beq	#0x26
        cmp	r2, #0x21
        bgt	#0x26
        subs	r2, #3
        movs	r1, r2
        b	#0x28
        movs	r1, #{l0}
        b	#0x28
        movs	r1, #{l1}
        b	#0x28
        movs	r1, #{l2}
        muls	r0, r1, r0
        """
        sig = bytes.fromhex("e083 b9f8 f620 4946")
        ofs = FindPattern(self.data, sig) + 6
        pre = self.data[ofs:ofs+42]
        post = bytes(self.ks.asm(asm)[0])
        #y = bytes.fromhex("00bf00bf00bf00bf002a08dd012a08d0022a08d0212a06dc033a110004e0062102e00c2100e014214843")
        #assert post == y
        self.data[ofs:ofs+42] = post
        ret.append(["dkc", hex(ofs), pre.hex(), post.hex()])

        return ret

    def lever_resolution(self, gas=0x7d, brake=0x73):
        '''
        '''
        ret = []

        if brake != 0x73:
            sig = bytes.fromhex("732800dd7320")
            ofs = FindPattern(self.data, sig)
            pre = self.data[ofs:ofs+2]
            post = bytes(self.ks.asm('cmp r0,#{}'.format(brake))[0])
            self.data[ofs:ofs+2] = post
            ret.append(["lever_res_brake1", hex(ofs), pre.hex(), post.hex()])

            ofs += 4
            pre = self.data[ofs:ofs+2]
            post = bytes(self.ks.asm('movs r0,#{}'.format(brake))[0])
            self.data[ofs:ofs+2] = post
            ret.append(["lever_res_brake2", hex(ofs), pre.hex(), post.hex()])

            ofs += 8
            pre = self.data[ofs:ofs+2]
            post = bytes(self.ks.asm('movs r2,#{}'.format(brake))[0])
            self.data[ofs:ofs+2] = post
            ret.append(["lever_res_brake3", hex(ofs), pre.hex(), post.hex()])

        # shouldn't be changed
        #if gas != 0x7d:
        #    sig = bytes.fromhex("7d2800dd7d20")
        #    ofs = FindPattern(self.data, sig)
        #    pre = self.data[ofs:ofs+2]
        #    post = bytes(self.ks.asm('cmp r0,#{}'.format(gas))[0])
        #    self.data[ofs:ofs+2] = post
        #    ret.append(["lever_res_gas1", hex(ofs), pre.hex(), post.hex()])

        #    ofs += 4
        #    pre = self.data[ofs:ofs+2]
        #    post = bytes(self.ks.asm('movs r0,#{}'.format(gas))[0])
        #    self.data[ofs:ofs+2] = post
        #    ret.append(["lever_res_gas2", hex(ofs), pre.hex(), post.hex()])

        #    ofs += 6
        #    pre = self.data[ofs:ofs+2]
        #    post = bytes(self.ks.asm('movs r1,#{}'.format(gas))[0])
        #    self.data[ofs:ofs+2] = post
        #    ret.append(["lever_res_gas3", hex(ofs), pre.hex(), post.hex()])

        return ret

    def brake_start_speed(self, kmh):
        '''
        WIP: brake stutter on low speeds
        '''
        val = struct.pack('<H', round(kmh * 345))
        sig = bytes.fromhex("026840f20b439a42")
        ofs = FindPattern(self.data, sig) + 2
        pre, post = PatchImm(self.data, ofs, 4, val, MOVW_T3_IMM)
        return [("bss", hex(ofs), pre.hex(), post.hex())]


if __name__ == "__main__":
    import sys
    from zippy.zippy import Zippy

    def eprint(*args, **kwargs):
        print(*args, file=sys.stderr, **kwargs)

    if len(sys.argv) != 4:
        eprint("Usage: {0} <orig-firmware.bin> <target.bin> [patches]".format(sys.argv[0]))
        exit(1)

    infile, outfile, args = sys.argv[1], sys.argv[2], sys.argv[3]

    with open(infile, 'rb') as fp:
        data = fp.read()

    mult = 10./8.5  # new while size / old wheel size

    vlt = FirmwarePatcher(data)

    #ret.extend(vlt.error_on_pair(2))
    #ret.extend(vlt.brakelight_mod())  # not compatible with relight
    #ret.extend(vlt.speedlimit_mod())  # not compatible with ltgm
    #ret.extend(vlt.reset_mode())

    patches = {
        'rlt':  lambda: vlt.relight_mod(reset=True, gm=True,
                                        dpc=True, beep=False,
                                        delay=False, autolight=False),
        'dpc':  lambda: vlt.dpc(),
        'sdt':  lambda: vlt.shutdown_time(1),
        'ss':   lambda: vlt.motor_start_speed(3),
        'wsc':  lambda: vlt.wheel_speed_const(mult),
        'sl':   lambda: vlt.speed_limit(22),
        'slg':  lambda: vlt.speed_limit_global(27),
        'slp':  lambda: vlt.speed_limit_pedo(9),
        'ap':   lambda: vlt.ampere_pedo(10000, 15000),
        'as':   lambda: vlt.ampere_speed(24000),
        'dkc':  lambda: vlt.dkc(l0=3),
        'ra':   lambda: vlt.remove_autobrake(),
        'rcm':  lambda: vlt.remove_charging_mode(),
        'crc':  lambda: vlt.current_raising_coeff(1000),
        'ccd':  lambda: vlt.cc_delay(2),
        'ltg':  lambda: vlt.ltgm(),
        'll':   lambda: vlt.lower_light(),
        'am':   lambda: vlt.amp_meter(real=True, shift=8),
        'lrb':  lambda: vlt.lever_resolution(brake=0x9c),
        #'lrg':  lambda: vlt.lever_resolution(gas=0x9c),
        #'bss':  lambda: vlt.brake_start_speed(2.0),
        'rcc':  lambda: vlt.rf_cc_unlock(),
        'rbl':  lambda: vlt.rf_bl_unlock(),
        'rdb':  lambda: vlt.rf_de_brake(),
    }

    for k in patches:
        if k not in args.split(","):
            continue
        try:
            for ofs, pre, post, desc in patches[k]():
                print(ofs, pre, post, desc)
        except SignatureException:
            print("sigerr", k)

    with open(outfile, 'wb') as fp:
        if outfile.endswith(".zip"):
            fp.write(Zippy(vlt.data).zip_it("ilike".encode()))
        else:
            fp.write(vlt.data)
