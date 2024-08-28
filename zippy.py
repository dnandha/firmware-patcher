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

import zipfile
import hashlib
import types
import sys
import json
from urllib import request
import os
from io import BytesIO


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

    def try_extract(self, decrypt=True, in_memory=True):
        """Extract the first file from a ZIP archive and return its content as bytes."""

        file_ = BytesIO(self.data)
        if not zipfile.is_zipfile(file_):
            return

        with zipfile.ZipFile(file_, 'r') as zip_ref:
            # List all files and directories in the ZIP file
            file_list = zip_ref.namelist()
            if not file_list:
                raise ValueError("The ZIP file is empty.")
            # Extract the first file (assuming non-directory)
            first_file_name = file_list[0]
            with zip_ref.open(first_file_name) as first_file:
                self.data = first_file.read()
                if not self.decode_model() and decrypt:
                    try:
                        self.data = self.decrypt(in_memory=in_memory)
                        self.decode_model()
                    except:
                        raise Exception("Decode error")

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

    def decrypt(self, in_memory=False):
        if in_memory:
            url = 'https://github.com/BotoX/xiaomi-m365-firmware-patcher/raw/master/xiaotea/xiaotea.py'
            response = request.urlopen(url)
            data = response.read()
            txt = data.decode('utf-8')
            xt = types.ModuleType('XT')
            exec(txt, xt.__dict__)
            return xt.XiaoTea().decrypt(self.data)
        else:
            from xiaotea import XiaoTea
            return XiaoTea().decrypt(self.data)

    @staticmethod
    def get_v3(name, model, md5, md5e, enforce):
        compatible_list = []
        if model in ["1s", "pro2", "lite", "3"]:
            compatible_list = ["mi_DRV_STM32F103CxT6"]
            if model != "4pro":
                compatible_list += ["mi_DRV_GD32F103CxT6", "mi_DRV_GD32E103CxT6"]
        elif model in ["f2", "f2plus", "f2pro"]:
            model = "f2"
            compatible_list += ["f2_DRV_AT32F415CxT7"]
        elif model in ["g2"]:
            compatible_list += ["g2_DRV_AT32F415CxT7"]

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

        zip_buffer = BytesIO()
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

    zippy = Zippy(data, name="ngfw")
    zippy.try_extract()

    with open(outfile, 'wb') as fp:
        fp.write(zippy.zip_it("nice".encode(), offline=False, enforce=False))
