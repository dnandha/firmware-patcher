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
#####
# Based on: https://github.com/BotoX/xiaomi-m365-firmware-patcher/blob/master/patcher.py
# I introduced mods into the patcher either by studying existing patchers or creating new mods myself.
# All original mod authors are mentioned in the function comments!
#####

from mi_patcher import MiPatcher
from nb_patcher import NbPatcher

from util import SignatureException


if __name__ == "__main__":
    import sys
    from argparse import ArgumentParser
    from zippy import Zippy

    parser = ArgumentParser()
    parser.add_argument("type", choices=['mi', 'nb'])
    parser.add_argument("infile")
    parser.add_argument("outfile")
    parser.add_argument("patches")
    args = parser.parse_args()

    def eprint(*args, **kwargs):
        print(*args, file=sys.stderr, **kwargs)


    with open(args.infile, 'rb') as fp:
        data = fp.read()

    mult = 10./8.5  # new while size / old wheel size

    if args.type == 'mi':
        vlt = MiPatcher(data)

        patches = {
            'dpc': lambda: vlt.dpc(),
            'sdt': lambda: vlt.shutdown_time(1),
            'mss': lambda: vlt.motor_start_speed(3),
            'wsc': lambda: vlt.wheel_speed_const(mult),
            'sld': lambda: vlt.speed_limit_drive(22),
            'sls': lambda: vlt.speed_limit_sport(27),
            'slp': lambda: vlt.speed_limit_ped(9),
            'amp': lambda: vlt.ampere_ped(10000),
            'amd': lambda: vlt.ampere_drive(20000),
            'ams': lambda: vlt.ampere_sport(30000),
            'alm': lambda: vlt.ampere_max(10000, 30000, 55000),
            'rml': lambda: vlt.remove_modellock(),
            'rks': lambda: vlt.remove_kers(),
            'rab': lambda: vlt.remove_autobrake(),
            'rcm': lambda: vlt.remove_charging_mode(),
            'crc': lambda: vlt.current_raising_coeff(1000),
            'ccd': lambda: vlt.cc_delay(2),
            'rfm': lambda: vlt.region_free(),
            'llm': lambda: vlt.lower_light(),
            'blm': lambda: vlt.brake_light(),
            'amm': lambda: vlt.ampere_meter(shift=8),
            'lrb': lambda: vlt.lever_resolution(brake=0x9c),
            'bud': lambda: vlt.bms_baudrate(76800),
            'vlt': lambda: vlt.volt_limit(43.01),
            'pnb': lambda: vlt.ped_noblink(),
            'bts': lambda: vlt.button_swap(),
            'fud': lambda: vlt.fake_uid("0102030405060708090A0B0C"),
            'abr': lambda: vlt.ampere_brake(min_=25000, max_=60000),
            'kml': lambda: vlt.kers_multi(2, 5, 10),
        }
    elif args.type == 'nb':
        vlt = NbPatcher(data)

        patches = {
            'dmn': lambda: vlt.disable_motor_ntc(),
            'asc': lambda: vlt.allow_sn_change(),
            'skc': lambda: vlt.skip_key_check(),
            'rfm': lambda: vlt.region_free()
        }

    for k in patches:
        if k not in args.patches.split(",") and args.patches != 'all':
            continue
        try:
            for desc, ofs, pre, post in patches[k]():
                print(desc, ofs)
                pre_dis = [' '.join([x.bytes.hex(), x.mnemonic, x.op_str])
                           for x in vlt.cs.disasm(bytes.fromhex(pre), 0)]
                post_dis = [' '.join([x.bytes.hex(), x.mnemonic, x.op_str])
                            for x in vlt.cs.disasm(bytes.fromhex(post), 0)]
                for pd in pre_dis:
                    print("<", pd)
                for pd in post_dis:
                    print(">", pd)
        except SignatureException:
            print("SIGERR", k)

    with open(args.outfile, 'wb') as fp:
        if args.outfile.endswith(".zip"):
            fp.write(Zippy(vlt.data).zip_it("ilike".encode()))
        else:
            fp.write(vlt.data)
