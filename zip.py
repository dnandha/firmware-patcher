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

        try:
            id_ = self.data[0x100:0x10f].decode('ascii')
        except UnicodeDecodeError:
            try:
                id_ = self.data[0x400:0x417].decode("ascii")
            except UnicodeDecodeError:
                try:
                    id_ = self.data[0x400:0x40e].decode('ascii')
                except UnicodeDecodeError:
                    pass

        self.model = None
        if model is not None:
            self.model = model
        else:
            match id_:
                case "Scooter_MiP2_V0":
                    self.model = "pro2"
                case "Scooter_Mi1S_V0":
                    self.model = "1s"
                case "Scooter_Mi3_V0":
                    self.model = "mi3"
                case "Scooter_Mi4P_ST_F103_V8":
                    self.model = "4pro"

    def check_valid(self):
        return self.model is not None

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
        compatible_list = ["mi_DRV_STM32F103CxT6"]
        if model != "4pro":
            compatible_list += ["mi_DRV_GD32F103CxT6", "mi_DRV_GD32E103CxT6"]
        data = {
            "schemaVersion": 1,
            "firmware": {
                "displayName": name,
                "model": model,
                "enforceModel": enforce,
                "type": "DRV",
                "compatible": compatible_list,
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
        fp.write(Zippy(data, name="ngfw").zip_it("nice".encode(), offline=True, enforce=False))
