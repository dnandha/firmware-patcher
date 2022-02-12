#!/usr/bin/python3
from binascii import hexlify, unhexlify
import struct
import keystone
#import capstone
from xiaotea import XiaoTea

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

    def encrypt(self):
        cry = XiaoTea()
        self.data = cry.encrypt(self.data)

    def brakelight_mod(self):
        ret = []

        sig = [0xA1, 0x79, 0x01, 0x29]
        ofs = FindPattern(self.data, sig)
        pre = self.data[ofs:ofs+2]
        post = bytes([int(x, 0) for x in ['0x00', '0x21']])
        self.data[ofs:ofs+2] = post
        ret.append([ofs, pre, post])

        sig = [0x90, 0xf8, 0x43, 0x00, 0x00, 0x28]
        ofs = FindPattern(self.data, sig) + 4

        pre = self.data[ofs:ofs+2]
        post = bytes([int(x, 0) for x in ['0x08', '0x28']])
        self.data[ofs:ofs+2] = post
        ret.append([ofs, pre, post])

        return ret

    def speed_plus2(self):
        ret = []

        sig = [0x95, 0xf8, 0x34, 0x20, 0x14, 0x21, 0x4f, 0xf4, 0x96, 0x70]
        ofs = FindPattern(self.data, sig) + 4
        pre = self.data[ofs:ofs+2]
        post = bytes([int(x, 0) for x in ['0x16', '0x21']])
        self.data[ofs:ofs+2] = post
        ret.append([ofs, pre, post])

        return ret

    def remove_kers(self):
        ret = []

        sig = [0x01, 0x40, 0x0a, 0x20, 0x3c, 0xe0, 0x00, 0x88]
        ofs = FindPattern(self.data, sig) + 2
        pre = self.data[ofs:ofs+2]
        post = bytes([int(x, 0) for x in ['0x01', '0x20']])
        self.data[ofs:ofs+2] = post
        ret.append([ofs, pre, post])

        ofs += 0x142

        pre = self.data[ofs:ofs+2]
        assert pre[0] == 0x49 and pre[1] == 0x42
        post = bytes([int(x, 0) for x in ['0xff', '0x21']])
        self.data[ofs:ofs+2] = post
        ret.append([ofs, pre, post])

        return ret

    def remove_autobrake(self):
        sig = [None, 0x68, 0x42, 0xf6, 0x6e, 0x0c]
        ofs = FindPattern(self.data, sig) + 2
        pre = self.data[ofs:ofs+4]
        post = bytes(self.ks.asm('MOVW IP, #0xffff')[0])
        self.data[ofs:ofs+4] = post
        return [(ofs, pre, post)]

    def remove_charging_mode(self):
        sig = [0xB8, 0xF8, 0x12, 0x00, 0x20, 0xB1, 0x84, 0xF8, 0x3A]
        ofs = FindPattern(self.data, sig) + 4
        pre = self.data[ofs:ofs+2]
        post = bytes(self.ks.asm('NOP')[0])
        self.data[ofs:ofs+2] = post
        return [(ofs, pre, post)]

    def motor_start_speed(self, kmh, wheelratio=1., const=345):
        ret = []

        if wheelratio != 1.:
            val = struct.pack('<H', int(const/wheelratio))
            sig = [0xB4, 0xF9, None, 0x00, 0x40, 0xF2, 0x59, 0x11, 0x48, 0x43]
            ofs = FindPattern(self.data, sig) + 4
            pre, post = PatchImm(self.data, ofs, 4, val, MOVW_T3_IMM)
            self.data[ofs:ofs+4] = post
            ret.append([ofs, pre, post])

        val = struct.pack('<H', int(kmh * const * wheelratio))
        sig = [0x28, 0x48, 0x01, 0x68, 0x40, 0xF2, 0xBD, 0x62, 0x27, 0x4F]
        ofs = FindPattern(self.data, sig) + 4
        pre, post = PatchImm(self.data, ofs, 4, val, MOVW_T3_IMM)
        ret.append([ofs, pre, post])

        return ret

    def speed_params(self, eco_ampere, normal_ampere, speed_ampere):
        ret = []

        # TODO: changing eco/normal doesn't seem to have an effect
        #sig = [0x41, 0xF6, 0x58, None, None, 0x42, 0x01, 0xD2]
        #ofs = FindPattern(self.data, sig)
        #pre = self.data[ofs:ofs+4]
        #reg = 0
        #if pre[-1] == 0x32:
        #    reg = 2  # DRV236
        #elif pre[-1] == 0x33:
        #    reg = 3  # DRV304
        #else:
        #    raise Exception("invalid firmware file")
        #post = bytes(self.ks.asm('MOVW R{}, #{:n}'.format(reg, eco_ampere))[0])
        #self.data[ofs:ofs+4] = post
        #ret.append([ofs, pre, post])
        #ofs += 4
        #pre = self.data[ofs:ofs+2]
        #post = bytes(self.ks.asm('CMP R0, R0')[0])
        #self.data[ofs:ofs+2] = post
        #ret.append([ofs, pre, post])

        #sig = [0x06, 0xD0, 0x22, 0x8E, None, None, None, 0x23, None, 0x42, 0x13, 0xD2]
        #ofs = FindPattern(self.data, sig) + 4
        #pre = self.data[ofs:ofs+4]
        #post = bytes(self.ks.asm('MOVW R3, #{:n}'.format(normal_ampere))[0])
        #self.data[ofs:ofs+4] = post
        #ret.append([ofs, pre, post])
        #ofs += 4
        #pre = self.data[ofs:ofs+2]
        #post = bytes(self.ks.asm('CMP R0, R0')[0])
        #self.data[ofs:ofs+2] = post
        #ret.append([ofs, pre, post])

        sig = [0x12, 0xE0, 0x22, 0x8E, None, None, None, None, None, 0x42, 0x01, 0xD2]
        ofs = FindPattern(self.data, sig) + 4
        pre = self.data[ofs:ofs+4]
        post = bytes(self.ks.asm('MOVW R3, #{:n}'.format(speed_ampere))[0])
        self.data[ofs:ofs+4] = post
        ret.append([ofs, pre, post])
        ofs += 4
        pre = self.data[ofs:ofs+2]
        post = bytes(self.ks.asm('CMP R0, R0')[0])
        self.data[ofs:ofs+2] = post
        ret.append([ofs, pre, post])

        return ret

    def dpc(self):
        ret = []
        sig = [0x25, 0x4a, 0x00, 0x21, 0xa1, 0x71, 0xa2, 0xf8, 0xec, 0x10, 0x63, 0x79]
        ofs = FindPattern(self.data, sig) + 6
        pre = self.data[ofs:ofs+2]
        post = bytes(self.ks.asm('NOP')[0])
        self.data[ofs:ofs+2] = post
        ret.append([ofs, pre, post])

        ofs += 2
        pre = self.data[ofs:ofs+2]
        post = bytes(self.ks.asm('NOP')[0])
        self.data[ofs:ofs+2] = post
        ret.append([ofs, pre, post])

        sig = [0xa4, 0xf8, 0xe2, None, 0xa4, 0xf8, 0xf0, None, 0xa4, 0xf8, 0xee, None]
        ofs = FindPattern(self.data, sig) + 4
        pre = self.data[ofs:ofs+4]
        reg = 0
        if pre[-1] == 0x70:
            reg = 7  # DRV236
        elif pre[-1] == 0x60:
            reg = 6  # DRV304
        else:
            raise Exception("invalid firmware file")
        post = bytes(self.ks.asm('STRH.W R{}, [R4, #0xEC]'.format(reg))[0])
        self.data[ofs:ofs+4] = post
        ret.append([ofs, pre, post])

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

    cfw = FirmwarePatcher(data)
    ret = cfw.brakelight_mod()
    ret = cfw.speed_plus2()
    ret = cfw.remove_kers()
    ret = cfw.remove_autobrake()
    ret = cfw.remove_charging_mode()
    ret = cfw.motor_start_speed(3., wheelratio=12./8.5)  # wheelratio = new_wheel_size / old_wheel_size
    ret = cfw.speed_params(7000, 17000, 27000)
    ret = cfw.dpc()
    for ofs, pre, post in ret:
        print(hex(ofs), pre.hex(), post.hex())

    # Don't flash encrypted firmware to scooter running firmware < 1.4.1
    #cfw.encrypt()

    with open(sys.argv[2], 'wb') as fp:
        fp.write(cfw.data)

