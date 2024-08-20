import struct

from base_patcher import BasePatcher
from util import PatchImm, FindPattern, NearestConst, SignatureException

# https://web.eecs.umich.edu/~prabal/teaching/eecs373-f10/readings/ARMv7-M_ARM.pdf
MOVW_T3_IMM = [*[None]*5, 11, *[None]*6, 15, 14, 13, 12, None, 10, 9, 8, *[None]*4, 7, 6, 5, 4, 3, 2, 1, 0]
MOVS_T1_IMM = [*[None]*8, 7, 6, 5, 4, 3, 2, 1, 0]


# TODO: use model instead of signature guessing
class MiPatcher(BasePatcher):
    def __init__(self, data, model):
        super().__init__(data, model)

    def remove_modellock(self):
        '''
        Creator/Author: NandTek
        Description: (New DRVs only) Removes the check that prevents cross-flashing DRV from another model
        '''
        try:
            # 017
            sig = [0x01, 0xeb, 0x00, 0x0c, 0x13, 0xf8, 0x00, 0x80,
                   0x9c, 0xf8, 0x04, 0xc0, 0xc4, 0x45]
            ofs = FindPattern(self.data, sig) + len(sig)
        except SignatureException:
            # 016 / 252 / 245
            sig = [None, 0x18, None, 0xf8, 0x00, 0xc0, None, 0x79, None, 0x45]
            ofs = FindPattern(self.data, sig) + len(sig)

        pre = self.data[ofs:ofs+2]
        post = pre.copy()
        if pre[-1] != 0xd0:
            raise Exception(f"invalid firmware file: {pre.hex()}")
        post[-1] = 0xe0
        self.data[ofs:ofs+2] = post
        return [("no_modellock", hex(ofs), pre.hex(), post.hex())]

    def remove_kers(self):
        '''
        Creator/Author: NandTek
        Description: Alternate (improved) version of No Kers Mod
        '''
        try:
            sig = [0x00, 0xeb, 0x80, 0x00, 0x80, 0x00, 0x80, 0x0a]
            ofs = FindPattern(self.data, sig) + 6
        except SignatureException:
            # 022
            sig = [0x00, 0xdd, 0x80, 0x20, 0xc0, 0x04, 0x00, 0x0c]
            ofs = FindPattern(self.data, sig) + 6
        pre = self.data[ofs:ofs+2]
        post = bytes(self.ks.asm('MOVS R0, #0')[0])
        self.data[ofs:ofs+2] = post
        return [("no_kers", hex(ofs), pre.hex(), post.hex())]

    def remove_autobrake(self):
        '''
        Creator/Author: BotoX
        '''
        reg = 12
        try:
            sig = [None, 0x68, 0x42, 0xf6, 0x6e, 0x0c]
            ofs = FindPattern(self.data, sig) + 2
        except SignatureException:
            # 022
            sig = [0x2C, 0xE0, 0x18, 0x68, 0x42, 0xF6, 0xD0, 0x7b]
            ofs = FindPattern(self.data, sig) + 4
            reg = 11
        post = bytes(self.ks.asm(f'MOVW R{reg}, #0xffff')[0])
        pre = self.data[ofs:ofs+4]
        self.data[ofs:ofs+4] = post
        return [("no_autobrake", hex(ofs), pre.hex(), post.hex())]

    def remove_charging_mode(self):
        '''
        Creator/Author: BotoX
        '''
        sig = [0xF8, 0x12, 0x00, 0x20, 0xB1, None, 0xF8, 0x3A, None, None, 0x7b]
        ofs = FindPattern(self.data, sig) + 3
        pre = self.data[ofs:ofs+2]
        post = bytes(self.ks.asm('NOP')[0])
        self.data[ofs:ofs+2] = post
        return [("no_charge", hex(ofs), pre.hex(), post.hex())]

    def current_raising_coeff(self, coeff):
        '''
        Creator/Author: SH
        '''
        ret = []

        # TODO: all trying to find same position
        reg = 0
        try:
            sig = [0x95, 0xf8, 0x34, None, None, 0x21, 0x4f, 0xf4, 0x96, 0x70]
            ofs = FindPattern(self.data, sig) + 6
        except SignatureException:
            try:
                # 242
                sig = [0x85, 0xf8, 0x40, 0x60, 0x95, 0xf8, 0x34, 0x30]
                ofs = FindPattern(self.data, sig) + 0x8
                reg = 2
            except SignatureException:
                try:
                    # 016
                    sig = [0x00, 0xe0, 0x2e, 0x72, 0x95, 0xf8, 0x34, 0xc0]
                    ofs = FindPattern(self.data, sig) + 0xa
                    reg = 1
                except SignatureException:
                    # 022
                    sig = [0x95, 0xf8, 0x34, 0xc0, 0x4f, 0xf4, 0x96, 0x73]
                    ofs = FindPattern(self.data, sig) + 4
                    reg = 3

        pre = self.data[ofs:ofs+4]
        post = bytes(self.ks.asm('MOVW R{}, #{}'.format(reg, coeff))[0])
        self.data[ofs:ofs+4] = post
        ret.append(["crc", hex(ofs), pre.hex(), post.hex()])
        return ret

    def speed_limit_drive(self, kmh):
        '''
        Creator/Author: BotoX
        '''
        ret = []

        # TODO: first two trying to find same position
        try:
            sig = [0x95, 0xf8, 0x34, None, None, 0x21, 0x4f, 0xf4, 0x96, 0x70]
            ofs = FindPattern(self.data, sig) + 4
            reg = 1
        except SignatureException:
            try:
                # 016
                sig = [0x00, 0xe0, 0x2e, 0x72, 0x95, 0xf8, 0x34, 0xc0]
                ofs = FindPattern(self.data, sig) + 0x8
                reg = 2
            except SignatureException:
                try:
                    # 242
                    sig = [0xa1, 0x85, 0x0f, 0x20, 0x20, 0x84]
                    ofs = FindPattern(self.data, sig) + 2
                    reg = 0
                except SignatureException:
                    # 022
                    sig = [0x59, 0x00, 0x14, 0x22, 0x46]
                    ofs = FindPattern(self.data, sig) + 2
                    reg = 2

        pre = self.data[ofs:ofs+2]
        post = bytes(self.ks.asm('MOVS R{}, #{}'.format(reg, kmh))[0])
        self.data[ofs:ofs+2] = post
        ret.append(["sl_drive", hex(ofs), pre.hex(), post.hex()])

        return ret

    def speed_limit_sport(self, kmh):
        '''
        Creator/Author: SH
        '''
        ret = []

        # TODO: all trying to find same position
        reg = 8
        try:
            # for 319 this moved to the top and 'movs' became 'mov.w'
            sig = [0x95, 0xf8, 0x34, None, None, 0x21, 0x4f, 0xf4, 0x96, 0x70]
            ofs = FindPattern(self.data, sig) + 0xe
        except SignatureException:
            try:
                # 242
                sig = [0x85, 0xf8, 0x40, 0x60, 0x95, 0xf8, 0x34, 0x30]
                ofs = FindPattern(self.data, sig) + 0xc
                reg = 12
            except SignatureException:
                try:
                    # 016
                    sig = [0x00, 0xe0, 0x2e, 0x72, 0x95, 0xf8, 0x34, 0xc0]
                    ofs = FindPattern(self.data, sig) + 0x12
                except SignatureException:
                    # 022
                    sig = [0x4f, 0xf0, 0x19, 0x0e, 0x4f, 0xf0, 0x05, 0x09]
                    ofs = FindPattern(self.data, sig)
                    reg = 14

        pre = self.data[ofs:ofs+4]
        assert pre[-1] == reg
        post = bytes(self.ks.asm('MOVW R{}, #{}'.format(reg, kmh))[0])
        self.data[ofs:ofs+4] = post
        ret.append(["sl_speed", hex(ofs), pre.hex(), post.hex()])

        return ret

    def speed_limit_ped(self, kmh):
        '''
        Creator/Author: NandTek
        Description: Speed limit of pedestrian mode
        '''
        ret = []

        # TODO: both trying to find same position
        try:
            sig = [0x4f, 0xf0, 0x05, None, 0x01, None, 0x02, 0xd1]
            ofs = FindPattern(self.data, sig)
        except SignatureException:
            try:
                # 016
                sig = [0x00, 0xe0, 0x2e, 0x72, 0x95, 0xf8, 0x34, 0xc0]
                ofs = FindPattern(self.data, sig) + 0x16
            except SignatureException:
                # 0x22
                sig = [0x4f, 0xf0, 0x05, 0x09, 0xbc, 0xf1, 0x01, 0x0f]
                ofs = FindPattern(self.data, sig)

        pre = self.data[ofs:ofs+4]
        reg = pre[-1]
        post = bytes(self.ks.asm('MOVW R{}, #{}'.format(reg, kmh))[0])
        self.data[ofs:ofs+4] = post
        ret.append(["sl_ped", hex(ofs), pre.hex(), post.hex()])

        return ret

    def motor_start_speed(self, kmh):
        '''
        Creator/Author: BotoX
        '''
        try:
            sig = [0x01, 0x68, 0x40, 0xF2, 0xBD, 0x62]
            ofs = FindPattern(self.data, sig) + 2
            val = struct.pack('<H', round(kmh * 345))
            pre, post = PatchImm(self.data, ofs, 4, val, MOVW_T3_IMM)
        except SignatureException:
            # 022
            sig = [0x01, 0x08, 0xb1, 0xf5, 0xff, 0x6f]
            ofs = FindPattern(self.data, sig) + 2
            pre = self.data[ofs:ofs+4]
            post = bytes(self.ks.asm("CMP.W R1, #{}".format(round(kmh*408)))[0])
            self.data[ofs:ofs+4] = post
        return [("mss", hex(ofs), pre.hex(), post.hex())]

    def wheel_speed_const(self, factor):
        '''
        Creator/Author: BotoX
        '''
        ret = []

        try:
            sig = [0xB4, 0xF9, None, 0x00, 0x40, 0xF2, 0x59, 0x11, 0x48, 0x43]
            ofs = FindPattern(self.data, sig) + 4

            val1 = struct.pack('<H', round(345/factor))
            val2 = struct.pack('<H', round(1387*factor))

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
        except SignatureException:
            # 022
            sig = [0xA4, 0xF8, 0x4A, 0x50, 0x6F, 0xF4, 0xCC, 0x70]
            ofs = FindPattern(self.data, sig) + 4

            val1 = int(round(408/factor))
            # TODO: val1 can be incompatible with MVN instruction
            val2 = int(round(1774*factor))

            pre = self.data[ofs:ofs+4]
            post = bytes(self.ks.asm(f'MVN R0,#{val1}')[0])
            self.data[ofs:ofs+4] = post
            ret.append(['wheel_speed_const_0', hex(ofs), pre.hex(), post.hex()])

            sig = [0xBD, 0xF9, 0x24, 0x50, 0x40, 0xF2, 0xEE, 0x66]
            ofs = FindPattern(self.data, sig) + 4
            pre = self.data[ofs:ofs+4]
            post = bytes(self.ks.asm(f'MOVW R6,#{val2}')[0])
            self.data[ofs:ofs+4] = post
            ret.append(["wheel_other_const_0", hex(ofs), pre.hex(), post.hex()])

            sig = [0xBD, 0xF9, 0x24, 0x60, 0x40, 0xF2, 0xEE, 0x67]
            ofs = FindPattern(self.data, sig) + 4
            pre = self.data[ofs:ofs+4]
            post = bytes(self.ks.asm(f"MOVW R7,#{val2}")[0])
            ret.append(["wheel_other_const_1", hex(ofs), pre.hex(), post.hex()])

        return ret

    def ampere_sport(self, amps, force=True):
        '''
        Creator/Author: SH
        '''
        ret = []

        val = struct.pack('<H', amps)

        if force:
            try:
                sig = [0x13, 0xD2, None, 0x85, None, 0xE0, None, 0x8E]
                ofs = FindPattern(self.data, sig) + 8
            except SignatureException:
                try:
                    # 242
                    sig = [0x88, 0x42, 0x01, 0xd2, 0xa0, 0x85, 0x00, 0xe0]
                    ofs = FindPattern(self.data, sig)
                except SignatureException:
                    try:
                        # 016
                        sig = [0x98, 0x42, 0x01, 0xd2, 0xe0, 0x85, 0x00, 0xe0]
                        ofs = FindPattern(self.data, sig)
                    except SignatureException:
                        # 022
                        sig = [0x60, 0x86, 0x2d, 0xe0, 0x58, 0x45, 0x01, 0xd2]
                        ofs = FindPattern(self.data, sig) + 4

            pre = self.data[ofs:ofs+2]
            post = bytes(self.ks.asm('CMP R0, R0')[0])
            self.data[ofs:ofs+2] = post
            ret.append(["amp_speed_nop", hex(ofs), pre.hex(), post.hex()])

        try:
            sig = [None, 0x21, 0x4f, 0xf4, 0x96, 0x70]
            ofs = FindPattern(self.data, sig) + 6
        except SignatureException:
            try:
                # 242
                sig = [0x85, 0xf8, 0x40, 0x60, 0x95, 0xf8, 0x34, 0x30]
                ofs = FindPattern(self.data, sig) + 0x10
            except SignatureException:
                try:
                    # 016
                    sig = [0x00, 0xe0, 0x2e, 0x72, 0x95, 0xf8, 0x34, 0xc0]
                    ofs = FindPattern(self.data, sig) + 0xe
                except SignatureException:
                    # 022
                    sig = [0x59, 0x00, None, 0x22, 0x46, 0xf2, 0x84, 0x7b]
                    ofs = FindPattern(self.data, sig) + 4

        pre, post = PatchImm(self.data, ofs, 4, val, MOVW_T3_IMM)
        ret.append(["amp_speed", hex(ofs), pre.hex(), post.hex()])

        return ret

    def ampere_drive(self, amps, force=True):
        '''
        Creator/Author: BotoX
        '''
        ret = []

        val = struct.pack('<H', amps)

        try:
            sig = [0x95, 0xf8, 0x40, None, 0x01, None, 0x06, 0xd0, None, 0x8e]
            ofs = FindPattern(self.data, sig) + 0xa
            pre, post = PatchImm(self.data, ofs, 4, val, MOVW_T3_IMM)
            ret.append(["amp_drive", hex(ofs), pre.hex(), post.hex()])
            ofs_f = ofs + 4
        except SignatureException:
            try:
                # 016
                sig = [0x95, 0xf8, 0x40, 0xc0, 0xbc, 0xf1, 0x01, 0x0f, 0x05, 0xd0]
                ofs = FindPattern(self.data, sig) + len(sig)
                pre, post = PatchImm(self.data, ofs, 4, val, MOVW_T3_IMM)
                ret.append(["amp_drive", hex(ofs), pre.hex(), post.hex()])
                ofs_f = ofs + 4
            except SignatureException:
                # 242: drive has same amps as speed
                sig = [0x88, 0x42, 0x09, 0xd2, 0xa0, 0x85, 0x08, 0xe0]
                ofs_f = FindPattern(self.data, sig)

        if force:
            pre = self.data[ofs_f:ofs_f+2]
            post = bytes(self.ks.asm('CMP R0, R0')[0])
            self.data[ofs_f:ofs_f+2] = post
            ret.append(["amp_drive_nop", hex(ofs_f), pre.hex(), post.hex()])

        return ret

    def ampere_ped(self, amps, force=False):
        '''
        Creator/Author: NandTek
        Description: Nominal current of pedestrian mode
        '''
        ret = []

        val = struct.pack('<H', amps)

        sig = [None, None, 0x41, 0xf6, 0x58, None, None, None, 0x01, 0xd2]
        ofs = FindPattern(self.data, sig) + 2

        pre, post = PatchImm(self.data, ofs, 4, val, MOVW_T3_IMM)
        ret.append(["amp_ped", hex(ofs), pre.hex(), post.hex()])

        if force:
            ofs += 4
            pre = self.data[ofs:ofs+2]
            post = bytes(self.ks.asm('CMP R0, R0')[0])
            self.data[ofs:ofs+2] = post
            ret.append(["amp_ped_nop", hex(ofs), pre.hex(), post.hex()])

        return ret

    def ampere_max(self, amps_ped=None, amps_drive=None, amps_sport=None):
        '''
        Creator/Author: BotoX/SH
        '''
        ret = []

        sig = [0xa4, 0xf8, None, None, 0x4f, 0xf4, 0xfa]
        ofs_p = FindPattern(self.data, sig) + 4

        reg = 0
        try:
            sig = [0x02, 0xd0, 0xa4, 0xf8, 0x22, 0x80, None, 0xe0, 0x61, 0x84, None, 0xe0]
            ofs = FindPattern(self.data, sig)

            b = self.data[ofs_p+3]
            if b == 0x52:  # 247
                reg = 2
                ofs_s = ofs - 6
                ofs_d = ofs + len(sig) + 6
            elif b == 0x53:  # 319
                reg = 3
                ofs_s = ofs - 8
                ofs_d = ofs + len(sig) + 8
            else:
                raise Exception(f"invalid firmware file: {hex(b)}")

            if amps_ped is not None:
                #pre, post = PatchImm(self.data, ofs, 4, val_ped, MOVW_T3_IMM)
                pre = self.data[ofs_p:ofs_p+4]
                post = bytes(self.ks.asm('MOVW R{},#{}'.format(reg, amps_ped))[0])
                self.data[ofs_p:ofs_p+4] = post
                ret.append(["amp_max_ped", hex(ofs_p), pre.hex(), post.hex()])

            if amps_drive is not None:
                #pre, post = PatchImm(self.data, ofs, 4, val_drive, MOVW_T3_IMM)
                pre = self.data[ofs_d:ofs_d+4]
                post = bytes(self.ks.asm('MOVW R{},#{}'.format(reg, amps_drive))[0])
                self.data[ofs_d:ofs_d+4] = post
                ret.append(["amp_max_drive", hex(ofs_d), pre.hex(), post.hex()])
        except SignatureException:
            # 242 / 016
            if amps_ped is not None:
                pre = self.data[ofs_p:ofs_p+4]
                post = bytes(self.ks.asm('MOVW R{},#{}'.format(reg, amps_ped))[0])
                self.data[ofs_p:ofs_p+4] = post
                ret.append(["amp_max_ped", hex(ofs_p), pre.hex(), post.hex()])

            try:
                # 242
                sig = [0x95, 0xf8, 0x34, 0x80, 0x4f, 0xf4, 0xfa, 0x43]
                ofs_s = FindPattern(self.data, sig) + 4
                reg = 3  # TODO: cleanup
            except SignatureException:
                try:
                    # 016
                    sig = [0x95, 0xf8, 0x43, 0xc0, 0x46, 0xf6, 0x60, 0x50]
                    ofs_d = FindPattern(self.data, sig) + 4

                    sig = [0x95, 0xf8, 0x43, 0xc0, 0x4d, 0xf2, 0xd8, 0x60]
                    ofs_s = FindPattern(self.data, sig) + 4
                except SignatureException:
                    # 022
                    sig = [0x95, 0xf8, 0x41, 0x00, 0x48, 0xf6, 0xb8, 0x0c]
                    ofs_d = FindPattern(self.data, sig) + 4

                    sig = [0x95, 0xf8, 0x41, 0x30, 0x4d, 0xf2, 0xd8, 0x60]
                    ofs_s = FindPattern(self.data, sig) + 4

                if amps_drive is not None:
                    pre = self.data[ofs_d:ofs_d+4]
                    reg_d = reg
                    if pre[-1] == 12:
                        reg_d = 12
                    post = bytes(self.ks.asm('MOVW R{},#{}'.format(reg_d, amps_drive))[0])
                    self.data[ofs_d:ofs_d+4] = post
                    ret.append(["amp_max_drive", hex(ofs_d), pre.hex(), post.hex()])
        if amps_sport is not None:
            #pre, post = PatchImm(self.data, ofs, 4, val_speed, MOVW_T3_IMM)
            pre = self.data[ofs_s:ofs_s+4]
            post = bytes(self.ks.asm('MOVW R{},#{}'.format(reg, amps_sport))[0])
            self.data[ofs_s:ofs_s+4] = post
            ret.append(["amp_max_speed", hex(ofs_s), pre.hex(), post.hex()])

        return ret

    def dpc(self):
        '''
        Creator/Author: SH
        '''
        ret = []
        try:
            sig = [0x00, 0x21, 0xa1, 0x71, 0xa2, 0xf8, 0xec, 0x10, 0x63, 0x79]
            ofs = FindPattern(self.data, sig) + 4
        except SignatureException:
            # 022
            sig = [0xdf, 0xf8, 0x28, 0x91, 0xa9, 0xf8, 0xec, 0x70, 0x69, 0x79]
            ofs = FindPattern(self.data, sig) + 4
        pre = self.data[ofs:ofs+4]
        post = bytes(self.ks.asm('NOP')[0])
        self.data[ofs:ofs+2] = post
        self.data[ofs+2:ofs+4] = post
        post = self.data[ofs:ofs+4]
        ret.append(["dpc_nop", hex(ofs), pre.hex(), post.hex()])

        sig = [0xf8, 0xe2, None, None, 0xf8, 0xf0, None, None, 0xf8, 0xee, None]
        ofs = FindPattern(self.data, sig) + 3

        b = self.data[ofs+3]
        reg = 0
        if b == 0x70:
            reg = 7  # 236 / 319
        elif b == 0x50:
            reg = 5  # 242
        elif b == 0x80:
            reg = 8
        else:
            raise Exception(f"invalid firmware file: {hex(b)}")

        b = self.data[ofs]
        reg2 = 0
        if b == 0xa4:
            reg2 = 4
        elif b == 0xa5:
            reg2 = 5 # 022
        else:
            raise Exception(f"Invalid firmware file: {hex(b)}")

        pre = self.data[ofs:ofs+4]
        post = bytes(self.ks.asm('STRH.W R{}, [R{}, #0xEC]'.format(reg, reg2))[0])
        self.data[ofs:ofs+4] = post
        ret.append(["dpc_reset", hex(ofs), pre.hex(), post.hex()])

        return ret

    def shutdown_time(self, seconds):
        '''
        Creator/Author: NandTek
        Description: Time to press power button before shutdown
        '''
        delay = int(seconds * 200)
        assert delay.bit_length() <= 12, 'bit length overflow'
        sig = [0xb0, 0xf5, 0xfa, 0x7f, 0x08, 0xd9, None, 0x79, 0x30, 0xb9]
        ofs = FindPattern(self.data, sig)
        pre = self.data[ofs:ofs+4]
        post = bytes(self.ks.asm('CMP.W R0, #{:n}'.format(delay))[0])
        self.data[ofs:ofs+4] = post
        return [("shutdown", hex(ofs), pre.hex(), post.hex())]

    def ped_noblink(self):
        '''
        Creator/Author: NandTek
        Description: Don't force backlight / blinking in ped mode
        '''
        ret = []

        sig = [0x01, 0x29, None, 0xd0, 0xa1, 0x79, 0x01, 0x29, None, 0xd0, 0x90, 0xf8, 0x34, 0x10, 0x01, 0x29]
        ofs = FindPattern(self.data, sig) + len(sig)

        pre = self.data[ofs:ofs+2]
        post = bytes(self.ks.asm('NOP')[0])
        self.data[ofs:ofs+2] = post
        ret.append(["pnb", hex(ofs), pre.hex(), post.hex()])

        try:
            #ofs += 30
            sig = [0x89, 0x07, 0x02, 0xd5, 0x90, 0xf8, None, 0x10, 0x19, 0xb3, 0x90, 0xf8, 0x34, 0x00, 0x01, 0x28]
            ofs = FindPattern(self.data, sig) + len(sig)
            pre = self.data[ofs:ofs+2]
            post = bytes(self.ks.asm('NOP')[0])
            self.data[ofs:ofs+2] = post
            ret.append(["pnb2", hex(ofs), pre.hex(), post.hex()])
        except SignatureException:
            # n/a on lite
            pass

        return ret

    def brake_light_static(self):
        '''
        Creator/Author: SH
        Description: Old mod version, fixed by NandTek
        '''
        ret = []

        sig = [0x01, 0x29, None, 0xd0, 0xa1, 0x79, 0x01, 0x29]
        ofs = FindPattern(self.data, sig) + 6
        pre = self.data[ofs:ofs+2]
        post = bytes(self.ks.asm('CMP R1, #0xff')[0])
        self.data[ofs:ofs+2] = post
        ret.append(["blm_throttle", hex(ofs), pre.hex(), post.hex()])

        ofs += 8
        pre = self.data[ofs:ofs+2]
        post = bytes(self.ks.asm('CMP R1, #0xff')[0])
        self.data[ofs:ofs+2] = post
        ret.append(["blm_ped", hex(ofs), pre.hex(), post.hex()])

        sig = [0x90, 0xf8, None, None, 0x00, 0x28, None, 0xd1]
        ofs = FindPattern(self.data, sig) + 4
        pre = self.data[ofs:ofs+2]
        post = bytes(self.ks.asm('CMP R0, #0xff')[0])
        self.data[ofs:ofs+2] = post
        ret.append(["blm_glob", hex(ofs), pre.hex(), post.hex()])

        return ret

    def brake_light(self):
        '''
        Creator/Author: NandTek
        Description: Alternate (improved) version,
                     instead of changing condition flags (hacky), replace code
        '''
        ret = []

        sig = [0x10, 0xbd, 0x00, 0x00, None, 0x04, 0x00, 0x20, 0x70, 0xb5]
        ofs = FindPattern(self.data, sig) + 4
        ofs_1 = self.data[ofs:ofs+4]
        ofs_1 = struct.unpack("<L", ofs_1)[0]

        sig = [None, 0x00, 0x00, 0x20, None, 0x06, 0x00, 0x20, None, 0x03, 0x00, 0x20]
        ofs = FindPattern(self.data, sig) + 0x8
        ofs_2 = self.data[ofs:ofs+4]
        ofs_2 = struct.unpack("<L", ofs_2)[0]
        adds = ofs_1 - ofs_2

        ofs = 0
        len_ = 46
        try:
            sig = [0x90, 0xf8, None, None, None, 0x28, None, 0xd1]
            ofs = FindPattern(self.data, sig) + 0x8
        except SignatureException:
            pass

        if not (ofs > 0 and ofs < 0x1000):
            # 242 / 245
            sig = [0xa0, 0x7d, 0x40, 0x1c, 0xc0, 0xb2, 0xa0, 0x75]
            ofs = FindPattern(self.data, sig)

        # smash stuff
        pre = self.data[ofs:ofs+len_]
        nopcount = ((len_ - 4) // 2)
        post = bytes(self.ks.asm('NOP')[0] * nopcount
                     + self.ks.asm('POP.W {R4, R5, R6, PC}')[0])
        assert len(post) == len_, len(post)
        self.data[ofs:ofs+len_] = post

        # duplicate "backlight on" code
        asm = """
        adds       r5,r4,#{}
        ldrh       r1,[r5,#0]
        mov.w      r6,#0x40000000
        strh       r1,[r6,#0x34]
        adds       r1,#0x10
        strh       r1,[r5,#0]
        cmp        r1,#0x60
        ble        #0x18
        movs       r1,#0x60
        strh       r1,[r5,#0]
        """.format(adds)

        patch = bytes(self.ks.asm(asm)[0])
        self.data[ofs:ofs+len(patch)] = patch
        post = self.data[ofs:ofs+len_]
        ret.append(["blm", hex(ofs), pre.hex(), post.hex()])
        return ret

    def region_free(self):
        '''
        Creator/Author: NandTek
        Description: Remove all region restrictions bound to serial number
        '''
        ret = []

        try:
            sig = self.ks.asm('STRB.W R2,[R1,#0x43]')[0]
            ofs = FindPattern(self.data, sig)
            pre = self.data[ofs:ofs+4]
            post = bytes(self.ks.asm('NOP')[0])
            self.data[ofs:ofs+2] = post
            self.data[ofs+2:ofs+4] = post
            post = self.data[ofs:ofs+4]
            ret.append(["rfm1", hex(ofs), pre.hex(), post.hex()])

            # 248 / 321 (unused in 016)
            sig = self.ks.asm('STRB R2,[R1,#0x1e]')[0]
            ofs = FindPattern(self.data, sig)
            pre = self.data[ofs:ofs+2]
            post = bytes(self.ks.asm('NOP')[0])
            self.data[ofs:ofs+2] = post
            post = self.data[ofs:ofs+2]
            ret.append(["rfm2", hex(ofs), pre.hex(), post.hex()])

            # 016 (unused in 248 / 321)
            sig = self.ks.asm('STRB.W R2,[R1,#0x41]')[0]
            ofs = FindPattern(self.data, sig)
            pre = self.data[ofs:ofs+4]
            post = bytes(self.ks.asm('NOP')[0])
            self.data[ofs:ofs+2] = post
            self.data[ofs+2:ofs+4] = post
            post = self.data[ofs:ofs+4]
            ret.append(["rfm3", hex(ofs), pre.hex(), post.hex()])
        except SignatureException:
            # 022
            flag_offsets = [0x3e, 0x41, 0x43, 0x44, 0x45]
            for i, f_ofs in enumerate(flag_offsets):
                sig = self.ks.asm(f"STRB.W R7,[R6,#{f_ofs}]")[0]
                ofs = FindPattern(self.data, sig)
                pre = self.data[ofs:ofs+4]
                post = bytes(self.ks.asm('NOP.W')[0])
                self.data[ofs:ofs+4] = post
                post = self.data[ofs:ofs+4]
                ret.append([f"rfm{i}", hex(ofs), pre.hex(), post.hex()])

        return ret

    def lower_light(self):
        '''
        Creator/Author: NandTek
        Description: Lowers light intensity, for auto-light effect
        '''
        ret = []
        sig = [0x4f, 0xf0, 0x80, 0x40, 0x04, 0xf0, None, None, 0x20, 0x88]
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

        return ret

    def ampere_meter(self, shift=8):
        '''
        Creator/Author: NandTek
        Description: Replace dashboard battery bars with amp meter
        '''
        ret = []

        asm = """
        ldr r1,[pc,#{}]
        ldr r0,[r{},#{}]
        asrs r0,r0,#{}
        bmi #0xc
        """
        addr_table = {
            # pre[0]: ofs1 reg ofs2
            0x80: [0xa0, 0, -0x30],  # 247
            0x90: [0xa0, 2, -0x30],  # 252
            0xa8: [0x9c, 5, -0x10],  # 319
        }

        sig = [None, 0x79, None, 0x49, 0x10, 0xb9, 0xfd, 0xf7, None, None, 0x48, 0x70]
        ofs = FindPattern(self.data, sig)
        pre = self.data[ofs:ofs+0xa]
        post = bytes(self.ks.asm(asm.format(*addr_table[pre[0]], shift))[0])
        self.data[ofs:ofs+0xa] = post
        ret.append(["ampere_meter", hex(ofs), pre.hex(), post.hex()])

        return ret

    def cc_delay(self, seconds):
        '''
        Creator/Author: BotoX
        '''
        ret = []

        delay = int(seconds * 200)

        reg = 0
        try:
            sig = [0xb0, 0xf8, 0xf8, 0x10, None, 0x4b, 0x4f, 0xf4, 0x7a, 0x70]
            ofs = FindPattern(self.data, sig) + 6
        except SignatureException:
            # 022
            sig = [0xf8, 0x00, 0x89, 0x46, 0x60, 0x4b, 0x4f, 0xf4, 0x7a, 0x71]
            ofs = FindPattern(self.data, sig) + 6
            reg = 1
        pre = self.data[ofs:ofs+4]
        post = bytes(self.ks.asm('MOV.W R{},#{}'.format(reg, delay))[0])
        self.data[ofs:ofs+4] = post
        ret.append(["cc_delay", hex(ofs), pre.hex(), post.hex()])

        return ret

    def lever_resolution(self, brake=0x73):
        '''
        Creator/Author: BotoX
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

        return ret

    def serial_unlock(self):
        # 016: 0x3df6 -> NOP
        # 321: 0x3cc0 -> NOP
        pass

    def bms_baudrate(self, val):
        '''
        Creator/Author: BotoX
        '''
        ret = []
        try:
            sig = [0x00, 0xf0, 0xe6, 0xf8, 0x00, 0x21, 0x4f, 0xf4, 0xe1, 0x30]
            ofs = FindPattern(self.data, sig) + 6
        except:
            # 022
            sig = [0x20, 0x46, 0x00, 0xf0, 0xa6, 0xfa, 0x4f, 0xf4, 0xe1, 0x30]
            ofs = FindPattern(self.data, sig) + 6
        pre = self.data[ofs:ofs+4]
        post = bytes(self.ks.asm('MOV.W R0,#{}'.format(val))[0])
        self.data[ofs:ofs+4] = post
        ret.append(["bms_baudrate", hex(ofs), pre.hex(), post.hex()])
        return ret

    def volt_limit(self, volts):
        '''
        Creator/Author: BotoX
        '''
        ret = []
        val = struct.pack('<H', int(volts * 100) - 2600)
        try:
            sig = [0x40, 0xF2, 0xA5, 0x61, 0xA0, 0xF6, 0x28, 0x20, 0x88, 0x42]
            ofs = FindPattern(self.data, sig)
        except SignatureException:
            # 022
            sig = [0x40, 0xf2, 0xa5, 0x61, 0x88, 0x42, 0x04, 0xd3, 0x18, 0x20]
            ofs = FindPattern(self.data, sig)
        pre, post = PatchImm(self.data, ofs, 4, val, MOVW_T3_IMM)
        ret.append(["volt_limit", hex(ofs), pre.hex(), post.hex()])
        return ret

    def button_swap(self):
        '''
        Creator/Author: NandTek
        Description: Switch function of single/double click -> next level hackery! Props if you understand this :)
        '''
        ret = []

        sig = [None, 0x00, 0x00, 0x20, 0x10, 0xb5, 0x00, 0x23, 0x1a, 0x46, 0x03, 0xe0]
        ofs_dat = FindPattern(self.data, sig)

        sig = [0x22, 0x71, 0x22, 0x81, 0xb8, 0x78, 0x10, 0xb1, 0xba, 0x70, 0x2a, 0x72,
               0x37, 0xe0, 0x64, 0x20, 0xb8, 0x70, 0x2e, 0x72, 0x33, 0xe0]
        ofs_light = FindPattern(self.data, sig)

        sig = [0x22, 0x71, 0x22, 0x81, 0x01, 0x78, 0x21, 0xb1, 0x01, 0x29, 0x07, 0xd0,
               0x02, 0x29, 0x10, 0xd1, 0x0a, 0xe0, 0x02, 0x21, 0x01, 0x70, 0x85, 0xf8,
               0x3d, 0x60, 0x02, 0xe0, 0x02, 0x70, 0x85, 0xf8, 0x3d, 0x20, 0x85, 0xf8,
               0x3c, 0x20, 0x04, 0xe0, 0x06, 0x70, 0x85, 0xf8, 0x3d, 0x20, 0x85, 0xf8,
               0x3c, 0x60, 0x22, 0x70, 0xe2, 0x80]
        ofs_mode = FindPattern(self.data, sig) - 2

        diff = ofs_mode - ofs_light
        fofs = diff + 2
        fj2 = fofs + 0x6
        fj4 = fj2 + 0xc

        # ldr offsets have to be rounded to words...
        dat = (ofs_dat - ofs_mode - 2) // 4 * 4
        dat += diff

        asm_light = f"""
         THIS:
             ldr        r0,[pc,{dat}]
             strb       r2,[r4,#0x4]
             strh       r2,[r4,#0x8]
             ldrb       r1,[r0,#0x0]
             cbz        r1,J1
             cmp        r1,#0x1
             beq        {fj2}
             b          {fj4}
         J1:
             movs       r1,#0x2
             strb       r1,[r0,#0x0]
             b          {fofs}
        """

        asm_mode = """
         FORK:
             b          OTHER

         THIS_:
             strb.w     r6,[r5,#0x3d]
             b          J3
         J2:
             strb       r2,[r0,#0x0]
             strb.w     r2,[r5,#0x3d]
         J3:
             strb.w     r2,[r5,#0x3c]
             b          EXIT2
         J4:
             strb       r6,[r0,#0x0]
             strb.w     r2,[r5,#0x3d]
             strb.w     r6,[r5,#0x3c]
             b          EXIT2

        OTHER:
             strb       r2,[r4,#0x4]
             strh       r2,[r4,#0x8]
             ldrb       r0,[r7,#0x2]
             cbz        r0,J5
             strb       r2,[r7,#0x2]
             strb       r2,[r5,#0x8]
             b          EXIT
         J5:
             movs       r0,#0x64
             strb       r0,[r7,#0x2]
             strb       r6,[r5,#0x8]
         EXIT:
             strb       r2,[r4,#0x0]
         EXIT2:
        """
        post_light = bytes(self.ks.asm(asm_light)[0])
        post_mode = bytes(self.ks.asm(asm_mode)[0])
        assert len(post_light) == 22
        assert len(post_mode) == 54

        pre_light = self.data[ofs_light:ofs_light+len(post_light)]
        pre_mode = self.data[ofs_mode:ofs_mode+len(post_mode)]

        self.data[ofs_light:ofs_light+len(post_light)] = post_light
        self.data[ofs_mode:ofs_mode+len(post_mode)] = post_mode

        ret.append(["bts_light", hex(ofs_light), pre_light.hex(), post_light.hex()])
        ret.append(["bts_mode", hex(ofs_mode), pre_mode.hex(), post_mode.hex()])

        return ret

    def fake_uid(self, uid):
        '''
        Creator/Author: NandTek
        Description: Fake MCU UID
        '''
        ret = []
        sig = [0xfd, 0xf7, None, None, None, 0x48, 0xb0, 0xf9, 0x00, 0x10, 0xb4, 0xf9, 0xb4, 0x21, 0x91, 0x42]
        ofs = FindPattern(self.data, sig)

        asm = """
            ldr             r0,[pc, #0x244]
            adds.w          r1,r4,#0x1b4
            bl              FUN
            b               LAB
            nop
        FUN:
            push.w          {r4,r5,r6,lr}
            adr             r2,#0x30
            ldm.w           r2,{r4,r5,r6}
            str             r4,[r0,#0x0]
            str             r5,[r0,#0x4]
            str             r6,[r0,#0x8]
            str             r4,[r1,#0x0]
            str             r5,[r1,#0x4]
            str             r6,[r1,#0x8]
            nop; nop; nop; nop; nop; nop; nop; nop;
            nop; nop; nop; nop; nop; nop; nop; nop;
            pop             {r4,r5,r6,pc}
        DAT:
            str.w          r0,[r0]
            str.w          r0,[r0]
            str.w          r0,[r0]
        LAB:
            nop
        """

        post = bytearray(self.ks.asm(asm)[0])
        pre = self.data[ofs:ofs+len(post)]

        # postfix
        ldr = pre[4:6]
        ldr[0] += 1  # ldr shifted down up one instruction
        post[0:2] = ldr  # copy correct ldr address
        post[-2-12:-2] = bytes.fromhex(uid)  # inject uid

        self.data[ofs:ofs+len(post)] = post
        ret.append(["fud", hex(ofs), pre.hex(), post.hex()])

        return ret

    def ampere_brake(self, min_=None, max_=None):
        '''
        Creator/Author: SH
        Description: Set brake current limits (patch min+max or max first)
        '''

        ret = []
        sig = [0x00, 0xdd, 0x73, 0x20, None, None, None, None, 0x50, 0x43, 0x73, 0x22, 0x90, 0xfb, 0xf2, 0xf0, None, None, 0x10, 0x1a]

        ofs = FindPattern(self.data, sig) + 4
        if max_ is not None:
            pre = self.data[ofs:ofs+4]
            post = bytes(self.ks.asm('MOVW R2,#{}'.format(max_))[0])
            self.data[ofs:ofs+4] = post
            ret.append(["abr_max", hex(ofs), pre.hex(), post.hex()])

        if min_ is not None:
            try:
                # 022
                sig = [0xf2, 0xf0, None, None, 0x10, 0x1a, 0xa0, 0xf5, 0xfa, 0x50]
                ofs = FindPattern(self.data, sig) + 6
            except SignatureException:
                ofs += 18
            pre = self.data[ofs:ofs+4]
            val = NearestConst(min_)
            assert abs(val-min_) < 100, "rounding outside tolerance"
            post = bytes(self.ks.asm('SUB.W R0,R0,#{}'.format(val))[0])
            self.data[ofs:ofs+4] = post
            ret.append(["abr_min", hex(ofs), pre.hex(), post.hex()])

        return ret

    def kers_multi(self, l0=6, l1=12, l2=20):
        '''
        Creator/Author: NandTek
        Description: Set multiplier values for KERS
        '''
        ret = []

        try:
            asm = f"""
            nop
            movs  r1, #{l0}
            b  MULT
            nop
            movs  r1, #{l1}
            b  MULT
            nop
            movs  r1, #{l2}
            MULT:
            muls  r0, r0, r1
            """
            sig = [0x00, 0xeb, 0x40, 0x00, 0x40, 0x00, 0x05, 0xe0, 0x00, 0xeb, 0x40, 0x00, 0x01, 0xe0, 0x00, 0xeb, 0x80, 0x00, 0x80, 0x00]
            ofs = FindPattern(self.data, sig)
        except SignatureException:
            asm = f"""
            nop.w
            nop.w
            movs  r1, #{l0}
            b  MULT
            nop.w
            nop.w
            movs  r1, #{l1}
            b  MULT
            nop
            movs  r1, #{l2}
            MULT:
            muls  r0, r0, r1
            lsrs    r0, r0, #0xa
            """
            # 022
            sig = [0x00, 0xeb, 0x40, 0x00, 0xc0, 0xf3, 0x55, 0x20, 0x20, 0x86, 0x0a, 0xe0, 0x00, 0xeb, 0x40, 0x00, 0xc0, 0xf3, 0x15, 0x20, 0x20, 0x86, 0x04, 0xe0, 0x00, 0xeb, 0x80, 0x00, 0xc0, 0xf3, 0x15, 0x20]
            ofs = FindPattern(self.data, sig)

        pre = self.data[ofs:ofs+len(sig)]
        post = bytes(self.ks.asm(asm)[0])
        assert len(pre) == len(post), f"{len(pre)}, {len(post)}"
        self.data[ofs:ofs+len(sig)] = post
        ret.append(["kers_multi", hex(ofs), pre.hex(), post.hex()])

        return ret
