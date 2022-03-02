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

# Structure based on https://github.com/BotoX/xiaomi-m365-firmware-patcher/blob/master/patcher.py

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

    def brakelight_mod(self):
        ret = []

        sig = [0x01, 0x29, None, 0xd0, 0xa1, 0x79, 0x01, 0x29]
        ofs = FindPattern(self.data, sig) + 4
        pre = self.data[ofs:ofs+2]
        post = bytes([int(x, 0) for x in ['0x00', '0x21']])
        self.data[ofs:ofs+2] = post
        ret.append(["blm", ofs, pre, post])

        sig = [0x90, 0xf8, None, None, 0x00, 0x28, None, 0xd1]
        ofs = FindPattern(self.data, sig) + 4

        pre = self.data[ofs:ofs+2]
        post = bytes([int(x, 0) for x in ['0x08', '0x28']])
        self.data[ofs:ofs+2] = post
        ret.append(["blm", ofs, pre, post])

        return ret

    def speed_plus2(self, global_=False):
        ret = []

        sig = [0x95, 0xf8, 0x34, None, None, 0x21, 0x4f, 0xf4, 0x96, 0x70]
        ofs = FindPattern(self.data, sig) + 4
        if global_:
            try:
                # 216 / 304
                sig = [0x01, 0x2b, 0x01, 0xd0, 0x19, 0x23, 0x09, 0xe0, 0x61, 0x84]
                ofs = FindPattern(self.data, sig) + 4
                pre = self.data[ofs:ofs+2]
                post = bytes([int(x, 0) for x in ['0x1b', '0x23']])
                self.data[ofs:ofs+2] = post
                ret.append(["spt_us", ofs, pre, post])
            except SignatureException:
                # for 316 this moved to the top and 'movs' became 'mov.w'
                ofs += 0xa
                pre = self.data[ofs:ofs+4]
                post = bytes(self.ks.asm('MOV.W R8, #0x1b')[0])
                self.data[ofs:ofs+4] = post
                ret.append(["spt_us", ofs, pre, post])
        else:
            pre = self.data[ofs:ofs+2]
            post = bytes(self.ks.asm('MOVS R1, #0x16')[0])
            self.data[ofs:ofs+2] = post
            ret.append(["spt_de", ofs, pre, post])

        return ret

    def remove_kers(self):
        ret = []

        sig = [0x01, 0x40, 0x0a, 0x20, 0x3c, 0xe0, 0x00, 0x88]
        ofs = FindPattern(self.data, sig) + 2
        pre = self.data[ofs:ofs+2]
        post = bytes([int(x, 0) for x in ['0x01', '0x20']])
        self.data[ofs:ofs+2] = post
        ret.append(["no_kers", ofs, pre, post])

        ofs += 0x142

        pre = self.data[ofs:ofs+2]
        assert pre[0] == 0x49 and pre[1] == 0x42
        post = bytes([int(x, 0) for x in ['0xff', '0x21']])
        self.data[ofs:ofs+2] = post
        ret.append(["no_kers", ofs, pre, post])

        return ret

    def remove_autobrake(self):
        sig = [None, 0x68, 0x42, 0xf6, 0x6e, 0x0c]
        ofs = FindPattern(self.data, sig) + 2
        pre = self.data[ofs:ofs+4]
        post = bytes(self.ks.asm('MOVW IP, #0xffff')[0])
        self.data[ofs:ofs+4] = post
        return [("no_autobrake", ofs, pre, post)]

    def motor_start_speed(self, kmh):
        val = struct.pack('<H', round(kmh * 345))
        sig = [0x01, 0x68, 0x40, 0xF2, 0xBD, 0x62]
        ofs = FindPattern(self.data, sig) + 2
        pre, post = PatchImm(self.data, ofs, 4, val, MOVW_T3_IMM)
        return [("mss", ofs, pre, post)]

    def remove_charging_mode(self):
        sig = [0xB8, 0xF8, 0x12, 0x00, 0x20, 0xB1, 0x84, 0xF8, 0x3A]
        ofs = FindPattern(self.data, sig) + 4
        pre = self.data[ofs:ofs+2]
        post = bytes(self.ks.asm('NOP')[0])
        self.data[ofs:ofs+2] = post
        return [("no_charge", ofs, pre, post)]

    def wheel_speed_const(self, factor, def1=345, def2=1387):
        '''
        Patch by NandTek
        Bigger wheels need special treatment
        '''
        ret = []

        val1 = struct.pack('<H', round(def1/factor))
        val2 = struct.pack('<H', round(def2*factor))

        sig = [0xB4, 0xF9, None, 0x00, 0x40, 0xF2, 0x59, 0x11, 0x48, 0x43]
        ofs = FindPattern(self.data, sig) + 4
        pre, post = PatchImm(self.data, ofs, 4, val1, MOVW_T3_IMM)
        ret.append(["wheel_speed_const_0", ofs, pre, post])
        ofs -= 0x18
        pre, post = PatchImm(self.data, ofs, 4, val1, MOVW_T3_IMM)
        ret.append(["wheel_speed_const_1", ofs, pre, post])

        sig = [0x60, 0x60, 0x60, 0x68, 0x40, 0xF2, 0x6B, 0x51, 0x48, 0x43]
        ofs = FindPattern(self.data, sig) + 4
        pre, post = PatchImm(self.data, ofs, 4, val2, MOVW_T3_IMM)
        ret.append(["wheel_other_const", ofs, pre, post])

        return ret

    def ampere(self, speed):
        '''
        Patch by NandTek
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
            ret.append(["amp_speed", ofs, pre, post])

            ofs += 4
            pre = self.data[ofs:ofs+2]
            post = bytes(self.ks.asm('CMP R0, R0')[0])
            self.data[ofs:ofs+2] = post
            ret.append(["amp_speed_nop", ofs, pre, post])
        else:
            # DRV316
            post = bytes(self.ks.asm('CMP R0, R0')[0])
            self.data[ofs:ofs+2] = post
            ret.append(["amp_speed_nop", ofs, pre, post])

            # moved up to speed limits section
            sig = [None, 0x21, 0x4f, 0xf4, 0x96, 0x70, 0x44, 0xf6, 0x20, 0x62]
            ofs = FindPattern(self.data, sig) + 6
            pre, post = PatchImm(self.data, ofs, 4, val, MOVW_T3_IMM)
            ret.append(["amp_speed", ofs, pre, post])

        return ret

    def dpc(self):
        '''
        Patch by NandTek
        '''
        ret = []
        sig = [0x25, 0x4a, 0x00, 0x21, 0xa1, 0x71, 0xa2, 0xf8, 0xec, 0x10, 0x63, 0x79]
        ofs = FindPattern(self.data, sig) + 6
        pre = self.data[ofs:ofs+2]
        post = bytes(self.ks.asm('NOP')[0])
        self.data[ofs:ofs+2] = post
        ret.append(["dpc_nop", ofs, pre, post])

        ofs += 2
        pre = self.data[ofs:ofs+2]
        post = bytes(self.ks.asm('NOP')[0])
        self.data[ofs:ofs+2] = post
        ret.append(["dpc_nop", ofs, pre, post])

        sig = [0xa4, 0xf8, 0xe2, None, 0xa4, 0xf8, 0xf0, None, 0xa4, 0xf8, 0xee, None]
        ofs = FindPattern(self.data, sig) + 4
        pre = self.data[ofs:ofs+4]
        reg = 0
        if pre[-1] == 0x70:
            reg = 7  # DRV236 / 316
        elif pre[-1] == 0x60:
            reg = 6  # DRV304
        else:
            raise Exception("invalid firmware file")
        post = bytes(self.ks.asm('STRH.W R{}, [R4, #0xEC]'.format(reg))[0])
        self.data[ofs:ofs+4] = post
        ret.append(["dpc_reset", ofs, pre, post])

        return ret

    def shutdown_time(self, seconds):
        '''
        Patch by NandTek
        '''
        delay = int(seconds * 100)
        assert delay.bit_length() <= 12, 'bit length overflow'
        sig = [0x0a, 0x60, 0xb0, 0xf5, 0xfa, 0x7f, 0x08, 0xd9]
        ofs = FindPattern(self.data, sig) + 2
        pre = self.data[ofs:ofs+4]
        post = bytes(self.ks.asm('CMP.W R0, #{:n}'.format(delay))[0])
        self.data[ofs:ofs+4] = post
        return [("shutdown", ofs, pre, post)]

    def ltgm(self):
        '''
        Patch by NandTek + Voodoo
        '''
        ret = []
        sig = [0x02, 0xd5, 0x90, 0xf8, 0x43, 0x10, None, 0xb3]
        ofs = FindPattern(self.data, sig) + 2
        pre = self.data[ofs:ofs+4]
        post = bytes(self.ks.asm('LDRB.W R1,[R0,#0x13a]')[0])
        self.data[ofs:ofs+4] = post
        ret.append(["ltgm11", ofs, pre, post])
        sig = [0x90, 0xf8, 0x43, 0x00, 0x00, 0x28, None, None, 0x20, 0x7e]
        ofs = FindPattern(self.data, sig)
        pre = self.data[ofs:ofs+4]
        post = bytes(self.ks.asm('LDRB.W R0,[R0,#0x13a]')[0])
        self.data[ofs:ofs+4] = post
        ret.append(["ltgm10", ofs, pre, post])
        sig = [0x2d, 0x4a, 0x92, 0xf8, 0x43, 0x20, 0x00, 0xe0]
        ofs = FindPattern(self.data, sig) + 2
        pre = self.data[ofs:ofs+4]
        post = bytes(self.ks.asm('LDRB.W R2,[R2,#0x13a]')[0])
        self.data[ofs:ofs+4] = post
        ret.append(["ltgm9", ofs, pre, post])
        sig = [0x17, 0x48, 0x90, 0xf8, 0x43, 0x00, 0x58, 0xb9]
        ofs = FindPattern(self.data, sig) + 2
        pre = self.data[ofs:ofs+4]
        post = bytes(self.ks.asm('LDRB.W R0,[R0,#0x13a]')[0])
        self.data[ofs:ofs+4] = post
        ret.append(["ltgm8", ofs, pre, post])
        sig = [0x85, 0xf8, 0x40, 0x60, 0x95, 0xf8, 0x43, 0x10, 0xe9, 0xb1]
        ofs = FindPattern(self.data, sig) + 4
        pre = self.data[ofs:ofs+4]
        post = bytes(self.ks.asm('LDRB.W R1,[R5,#0x13a]')[0])
        self.data[ofs:ofs+4] = post
        ret.append(["ltgm7", ofs, pre, post])
        sig = [0x85, 0xf8, 0x40, 0x60, 0x95, 0xf8, 0x43, 0x10, 0x49, 0xb1]
        ofs = FindPattern(self.data, sig) + 4
        pre = self.data[ofs:ofs+4]
        post = bytes(self.ks.asm('LDRB.W R1,[R5,#0x13a]')[0])
        self.data[ofs:ofs+4] = post
        ret.append(["ltgm6", ofs, pre, post])

        # different in 316: r12 instead of r3
        sig = [0x00, 0xe0, None, 0x85, 0x95, 0xf8, 0x43, None]
        ofs = FindPattern(self.data, sig) + 4
        pre = self.data[ofs:ofs+4]
        reg = -1
        if pre[-1] == 0x30:  # 236 / 304
            reg = 3
        elif pre[-1] == 0xc0:  # 316
            reg = 12
        else:
            raise Exception("invalid firmware file")
        post = bytes(self.ks.asm('LDRB.W R{},[R5,#0x13a]'.format(reg))[0])
        self.data[ofs:ofs+4] = post
        ret.append(["ltgm5", ofs, pre, post])
        ofs += 0x16 if reg==3 else 0x1c
        pre = self.data[ofs:ofs+4]
        post = bytes(self.ks.asm('LDRB.W R{},[R5,#0x13a]'.format(reg))[0])
        self.data[ofs:ofs+4] = post
        ret.append(["ltgm4", ofs, pre, post])

        sig = [None, 0x65, 0x95, 0xf8, 0x43, None, None, 0xb9]
        ofs = FindPattern(self.data, sig) + 2
        pre = self.data[ofs:ofs+4]
        reg = -1
        if pre[-1] == 0x0:  # 236 / 316
            reg = 0
        elif pre[-1] == 0x10:  # 304
            reg = 1
        else:
            raise Exception("invalid firmware file")
        post = bytes(self.ks.asm('LDRB.W R{},[R5,#0x13a]'.format(reg))[0])
        self.data[ofs:ofs+4] = post
        ret.append(["ltgm3", ofs, pre, post])
        ofs += 0xe
        pre = self.data[ofs:ofs+4]
        post = bytes(self.ks.asm('LDRB.W R{},[R5,#0x13a]'.format(reg))[0])
        self.data[ofs:ofs+4] = post
        ret.append(["ltgm2", ofs, pre, post])

        try:
            # removed in 314 (power reduction)
            sig = [0xa0, 0x85, 0x95, 0xf8, 0x43, 0x00, 0x40, 0xf2, 0x59, 0x11]
            ofs = FindPattern(self.data, sig) + 2
            pre = self.data[ofs:ofs+4]
            post = bytes(self.ks.asm('LDRB.W R0,[R5,#0x13a]')[0])
            self.data[ofs:ofs+4] = post
            ret.append(["ltgm1", ofs, pre, post])
        except SignatureException:
            # added in 314 (extra check to decrease speed limit)
            sig = [0x82, 0x80, 0x95, 0xf8, 0x43, 0x20, 0x01, 0x2a, 0x0d, 0xd0]
            ofs = FindPattern(self.data, sig) + 2
            pre = self.data[ofs:ofs+4]
            post = bytes(self.ks.asm('LDRB.W R2,[R5,#0x13a]')[0])
            self.data[ofs:ofs+4] = post
            ret.append(["ltgm1", ofs, pre, post])

        sig = [None, 0x2b, None, 0xd1, 0x81, 0xf8, 0x43, 0x20, None, 0x78]
        ofs = FindPattern(self.data, sig) + 4
        pre = self.data[ofs:ofs+4]
        post = bytes(self.ks.asm('STRB.W R2,[R1,#0x13a]')[0])
        self.data[ofs:ofs+4] = post
        ret.append(["ltgm0", ofs, pre, post])

        return ret

    def mode_reset(self, reset_lgtm=True):
        '''
        Patch by NandTek
        Reset register flag while switching from speed to eco mode
        '''
        ret = []
        if reset_lgtm:
            sig = [0x01, 0x29, 0x07, 0xd0, 0x02, 0x29, 0x10, 0xd1, 0x0a, 0xe0]
            ofs = FindPattern(self.data, sig) + 4
            pre = self.data[ofs:ofs+4]
            post = bytes(self.ks.asm('STRB.W R6,[R5,#0x13a]')[0])
            self.data[ofs:ofs+4] = post
            ret.append(["ltgm-1", ofs, pre, post])

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
    ret.extend(vlt.ltgm())  # do this first
    ret.extend(vlt.brakelight_mod())
    ret.extend(vlt.dpc())
    ret.extend(vlt.shutdown_time(2))
    ret.extend(vlt.motor_start_speed(4))
    ret.extend(vlt.wheel_speed_const(mult))
    ret.extend(vlt.speed_plus2())
    ret.extend(vlt.speed_plus2(True))
    ret.extend(vlt.ampere(30000))
    ret.extend(vlt.remove_kers())
    ret.extend(vlt.remove_autobrake())
    ret.extend(vlt.remove_charging_mode())
    for desc, ofs, pre, post in ret:
        print(hex(ofs), pre.hex(), post.hex(), desc)

    with open(sys.argv[2], 'wb') as fp:
        fp.write(vlt.data)
