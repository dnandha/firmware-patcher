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

    def remove_kers(self):
        '''
        '''
        ret = []

        sig = [0x01, 0x40, 0x0a, 0x20, 0x3c, 0xe0, 0x00, 0x88]
        ofs = FindPattern(self.data, sig) + 2
        pre = self.data[ofs:ofs+2]
        post = bytes([int(x, 0) for x in ['0x01', '0x20']])
        self.data[ofs:ofs+2] = post
        ret.append(["no_kers", hex(ofs), pre.hex(), post.hex()])

        ofs += 0x142

        pre = self.data[ofs:ofs+2]
        assert pre[0] == 0x49 and pre[1] == 0x42
        post = bytes([int(x, 0) for x in ['0xff', '0x21']])
        self.data[ofs:ofs+2] = post
        ret.append(["no_kers", hex(ofs), pre.hex(), post.hex()])

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

    def ampere(self, speed):
        '''
        More current <=> more consumption
        '''
        ret = []

        val = struct.pack('<H', speed)

        sig = [0x13, 0xD2, None, 0x85, None, 0xE0, None, 0x8E]
        ofs = FindPattern(self.data, sig) + 8
        pre = self.data[ofs:ofs+2]
        if pre[0] <= 0x46 and pre[1] >= 0xf2:
            # DRV216 / 304
            pre, post = PatchImm(self.data, ofs, 4, val, MOVW_T3_IMM)
            ret.append(["amp_speed", hex(ofs), pre.hex(), post.hex()])

            ofs += 4
            pre = self.data[ofs:ofs+2]
            post = bytes(self.ks.asm('CMP R0, R0')[0])
            self.data[ofs:ofs+2] = post
            ret.append(["amp_speed_nop", hex(ofs), pre.hex(), post.hex()])
        else:
            # DRV319 / 247
            post = bytes(self.ks.asm('CMP R0, R0')[0])
            self.data[ofs:ofs+2] = post
            ret.append(["amp_speed_nop", hex(ofs), pre.hex(), post.hex()])

            # moved up to speed limits section
            sig = [None, 0x21, 0x4f, 0xf4, 0x96, 0x70]
            ofs = FindPattern(self.data, sig) + 6
            pre, post = PatchImm(self.data, ofs, 4, val, MOVW_T3_IMM)
            ret.append(["amp_speed", hex(ofs), pre.hex(), post.hex()])

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

        assert len(ret) in [11, 12], len(ret)

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

    def relight_mod(self, throttle_pos=0x9c, brake_pos=0x3c, reset=True, gm=True, dpc=True, beep=True, delay=True):
        '''
        Set / Reset with Throttle + Brake
        '''
        ret = []

        addr_table = {
            # ofs: [beep,  bcs,  ldr,  thrtl]
            0x662: [0x332, 0x3c, 0x78, 0x274],  # 319
            0x6de: [0x332, 0x3c, 0x78, 0x278],  # 247
            0x732: [0x39e, 0x34, 0x80, 0x278],  # 304
            0x73a: [0x38e, 0x3c, 0x78, 0x278],  # 236
        }

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
            asm = """
            ldrb       r6,[r4,#0x18]
            adds       r6,r6,#0x1
            uxtb       r6,r6
            strb       r6,[r4,#0x18]
            cmp        r6,#0xc8
            bls        #0x24
            strb       r5,[r4,#0x18]
            """

        asm += "MOVS R4,#0x1\n"
        if gm:
            #asm += "STRB.W R{}, [R0, #0x43]\n".format(4 if reset else 5)
            asm += "STRH.W R{}, [R0, #0x13a]\n".format(4 if reset else 5)
        if dpc:
            asm += "STRH.W R{}, [R0, #0x132]\n".format(5 if reset else 4)
        addr_f = addr_table[ofs][0]
        if beep:
            asm += "movs r0,#0x1\n"
            asm += f"bl #{addr_f}\n"

        post = bytes(self.ks.asm(asm)[0])
        self.data[ofs:ofs+len(post)] = post
        ret.append(["rl_payload", hex(ofs), pre.hex(), self.data[ofs:ofs+54].hex()])

        addr_b, addr_l, addr_t = addr_table[ofs][1:4]
        # main mod
        asm = f"""
        LDR     R6, {addr_l}
        LDRB.W  R1, [R6, #{addr_t}]
        CMP     R1, #{throttle_pos}
        BCC     0x14
        LDRB.W  R6, [R6, #{addr_t+1}]
        CMP     R6, #{brake_pos}
        BCS     {addr_b}
        NOP
        """
        sig = [None, 0x4c, 0x00, 0x25, 0x61, 0x79, 0x01, 0x29, None, 0xd0]
        ofs = FindPattern(self.data, sig) + 4
        pre = self.data[ofs:ofs+20]
        post = bytes(self.ks.asm(asm)[0])
        assert len(post) == 20, len(post)
        self.data[ofs:ofs+20] = post
        ret.append(["rl_hook", hex(ofs), pre.hex(), post.hex()])

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

    def cc_unlock(self):
        '''
        '''
        ret = []

        sig = bytes.fromhex("1748 90f8 4300 58b9")
        ofs = FindPattern(self.data, sig) + 6
        pre = self.data[ofs:ofs+2]
        post = bytes(self.ks.asm('NOP')[0])
        self.data[ofs:ofs+2] = post
        ret.append(["cc_unlock", hex(ofs), pre.hex(), post.hex()])

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

    def dkc(self):
        '''
        '''
        ret = []

        asm = """
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
        movs	r1, #6
        b	#0x28
        movs	r1, #0xc
        b	#0x28
        movs	r1, #0x14
        muls	r0, r1, r0
        """
        sig = bytes.fromhex("e083 b9f8 f620 4946")
        ofs = FindPattern(self.data, sig) + 6
        pre = self.data[ofs:ofs+42]
        post = bytes(self.ks.asm(asm)[0])
        y = bytes.fromhex("00bf00bf00bf00bf002a08dd012a08d0022a08d0212a06dc033a110004e0062102e00c2100e014214843")
        assert post == y
        self.data[ofs:ofs+42] = post
        ret.append(["dkc", hex(ofs), pre.hex(), post.hex()])

        return ret


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        eprint("Usage: {0} <orig-firmware.bin> <target.bin>".format(sys.argv[0]))
        exit(1)

    with open(sys.argv[1], 'rb') as fp:
        data = fp.read()

    mult = 10./8.5  # new while size / old wheel size

    vlt = FirmwarePatcher(data)

    ret = []
    ##ret.extend(vlt.brakelight_mod())  # not compatible with relight
    ret.extend(vlt.relight_mod(beep=False, delay=False))  # must come first
    ret.extend(vlt.dpc())
    ret.extend(vlt.shutdown_time(2))
    ret.extend(vlt.motor_start_speed(3))
    #ret.extend(vlt.wheel_speed_const(mult))
    #ret.extend(vlt.speed_limit(22))
    #ret.extend(vlt.speed_limit_global(27))
    #ret.extend(vlt.ampere(30000))
    ##ret.extend(vlt.remove_kers())
    ret.extend(vlt.dkc())
    #ret.extend(vlt.remove_autobrake())
    #ret.extend(vlt.remove_charging_mode())
    #ret.extend(vlt.current_raising_coeff(1000))  # do this last
    ##ret.extend(vlt.speedlimit_mod())  # not compatible with ltgm
    #ret.extend(vlt.cc_delay(2))
    #ret.extend(vlt.cc_unlock())
    ret.extend(vlt.ltgm())
    #ret.extend(vlt.reset_mode())
    for desc, ofs, pre, post in ret:
        print(ofs, pre, post, desc)

    with open(sys.argv[2], 'wb') as fp:
        fp.write(vlt.data)
