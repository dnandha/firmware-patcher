#!/usr/bin/python3
#
# XNG Firmware Patcher
# Copyright (C) 2021-2022 Daljeet Nandha
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
######
# Zip.py is a wrapper for XiaoTea
# (https://github.com/BotoX/xiaomi-m365-firmware-patcher/tree/master/xiaotea)
#####

import io
import zipfile
import hashlib
import types
import sys
import json
from urllib import request
import os


ROOTPATH = os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.realpath(__file__))))

FILENAME = "FIRM"
EXT_IN = ".bin"
EXT_OUT = ".zip"


class Zippy():
    def __init__(self, data, params=None, model=None, name="ngfw"):
        self.data = bytearray(data)
        self.name = name

        self.params = params

        self.model = model

        if self.model is None:
            try:
                id_ = data[0x100:0x10f].decode('ascii')
            except UnicodeDecodeError:
                try:
                    id_ = data[0x400:0x40e].decode('ascii')
                except UnicodeDecodeError:
                    raise Exception('Invalid file.')

            if id_ == "Scooter_MiP2_V0":
                self.model = "pro2"
            elif id_ == "Scooter_Mi1S_V0":
                self.model = "1s"
            elif id_ == "Scooter_Mi3_V0":
                self.model = "mi3"
            else:
                raise Exception('Invalid file.')

    def check_valid(self, data):
        md5 = hashlib.md5()
        md5.update(data)
        valid_md5s = [
            "116381392460d655b6a76c24d4afd694", # mi3/DRV016
            "69673d4463659d531837e7fb9a4300b6", # mi3/DRV017
            "ab83621ad43d493504359e69c3911b6c", # lite/DRV242
            "0e6268dfcb539b6c7319da3a7bc5bbe3", # lite/DRV245
            "3dbd7af96d90aaab326765ea367e586a", # pro2/DRV247
            "39d256fd99a7670d57b957b007cca42c", # pro2/DRV248
            "cbf77ea3557f8231d957e4a87fca63f7", # pro2/DRV252
            "aa70bd3bcd329eb00953afa1e0cc1888", # 1s/DRV319
            "26d8eb9abc836ee709cf9abdb2cd463a", # 1s/DRV321
        ]
        return md5.hexdigest() in valid_md5s

    def encrypt(self, in_memory=False):
        if in_memory:
            url = 'https://github.com/BotoX/xiaomi-m365-firmware-patcher/raw/master/xiaotea/xiaotea.py'
            response = request.urlopen(url)
            data = response.read()
            txt = data.decode('utf-8')
            xt = types.ModuleType('XT')
            exec(txt, xt.__dict__)
            return xt.XiaoTea().encrypt(self.data)
        else:
            from xiaotea import XiaoTea
            return XiaoTea().encrypt(self.data)

    @staticmethod
    def get_v3(name, model, md5, md5e, enforce):
        data = {
            "schemaVersion": 1,
            "firmware": {
                "displayName": name,
                "model": model,
                "enforceModel": enforce,
                "type": "DRV",
                "compatible": [
                    "mi_DRV_STM32F103CxT6",
                    "mi_DRV_GD32F103CxT6",
                    "mi_DRV_GD32E103CxT6"
                ],
                "encryption": "both",
                "md5": {
                    "bin": md5,
                    "enc": md5e
                }
            }
        }
        return json.dumps(data)

    def zip_it(self, comment, offline=False, enforce=True):
        md5 = hashlib.md5()
        md5.update(self.data)

        zip_buffer = io.BytesIO()
        zip_file = zipfile.ZipFile(zip_buffer, 'a', zipfile.ZIP_DEFLATED, False)

        zip_file.writestr('FIRM.bin', self.data)

        enc_data = self.encrypt(in_memory=not offline)
        zip_file.writestr('FIRM.bin.enc', enc_data)
        md5e = hashlib.md5()
        md5e.update(enc_data)

        info_txt = 'dev: {};\nnam: {};\nenc: B;\ntyp: DRV;\nmd5: {};\nmd5e: {};\n'.format(
            self.model, self.name, md5.hexdigest(), md5e.hexdigest())
        zip_file.writestr('info.txt', info_txt.encode())

        info_json = Zippy.get_v3(self.name, self.model, md5.hexdigest(), md5e.hexdigest(), enforce)
        zip_file.writestr('info.json', info_json.encode())

        if self.params is not None:
            zip_file.writestr('params.txt', self.params.encode())

        zip_file.comment = comment
        zip_file.close()
        zip_buffer.seek(0)
        content = zip_buffer.getvalue()
        zip_buffer.close()

        return content


if __name__ == "__main__":
    infile = None
    outfile = None
    if len(sys.argv) == 1:
        infile = FILENAME + EXT_IN
        infile = os.path.join(ROOTPATH, infile)
        outfile = FILENAME + EXT_OUT
        outfile = os.path.join(ROOTPATH, outfile)
    elif len(sys.argv) == 2:
        infile = sys.argv[1]
        outfile = infile.replace(".bin", ".zip")
    else:
        infile = sys.argv[1]
        outfile = sys.argv[2]

    with open(infile, 'rb') as fp:
        data = fp.read()

    with open(outfile, 'wb') as fp:
        fp.write(Zippy(data, name="ngfw").zip_it("nice".encode(), offline=True))
