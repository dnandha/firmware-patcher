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

# Based on https://github.com/BotoX/xiaomi-m365-firmware-patcher/blob/master/web/app.py

import flask
import traceback
import os
import time
import io
import zipfile
import hashlib


from patcher import FirmwarePatcher

app = flask.Flask(__name__)

@app.errorhandler(Exception)
def handle_bad_request(e):
    return 'Exception occured:\n{}'.format(traceback.format_exc()), \
            400, {'Content-Type': 'text/plain'}


# http://flask.pocoo.org/snippets/40/
@app.context_processor
def override_url_for():
    return dict(url_for=dated_url_for)


def dated_url_for(endpoint, **values):
    if endpoint == 'static':
        filename = values.get('filename', None)
        if filename:
            file_path = os.path.join(app.root_path,
                                     endpoint, filename)
            values['q'] = int(os.stat(file_path).st_mtime)
    return flask.url_for(endpoint, **values)


@app.route('/')
def home():
    return flask.render_template('home.html')


@app.route('/cfw', methods=['POST'])
def patch_firmware():
    f = flask.request.files['filename']

    data = f.read()
    md5 = hashlib.md5(data).hexdigest()
    if md5 == '194df3966443d8a913b47006119d45d9':
        version = "DRV236"
    elif md5 == '682fc3b89122ff0a21ebe2fa3ada4908':
        version = "DRV304"
    else:
        return 'Falsche oder keine Datei ausgewählt.', 400

    # make zip file for firmware
    zip_buffer = io.BytesIO()
    zip_file = zipfile.ZipFile(zip_buffer, 'a', zipfile.ZIP_DEFLATED, False)

    patcher = FirmwarePatcher(data)

    ltgm = flask.request.form.get('ltgm', None)
    if ltgm:
        print("ltgm")
        patcher.ltgm()

    dpc = flask.request.form.get('dpc', None)
    if dpc:
        print("dpc")
        patcher.dpc()

    brakelight_mod = flask.request.form.get('brakelight_mod', None)
    if brakelight_mod:
        print("blm")
        patcher.brakelight_mod()

    speed_plus2 = flask.request.form.get('speed_plus2', None)
    if speed_plus2:
        print("spt")
        patcher.speed_plus2()

    speed_plus2_global = flask.request.form.get('speed_plus2_global', None)
    if speed_plus2_global:
        print("sptg")
        patcher.speed_plus2(True)

    remove_autobrake = flask.request.form.get('remove_autobrake', None)
    if remove_autobrake:
        print("ra")
        patcher.remove_autobrake()

    remove_kers = flask.request.form.get('remove_kers', None)
    if remove_kers:
        print("rk")
        patcher.remove_kers()

    motor_start_speed = flask.request.form.get('motor_start_speed', None)
    if motor_start_speed is not None:
        print("mss", motor_start_speed)
        motor_start_speed = float(motor_start_speed)
        assert motor_start_speed >= 0 and motor_start_speed <= 100
        patcher.motor_start_speed(motor_start_speed)

    remove_charging_mode = flask.request.form.get('remove_charging_mode', None)
    if remove_charging_mode:
        print("rc")
        patcher.remove_charging_mode()

    wheelsize = flask.request.form.get('wheelsize', None)
    if wheelsize is not None:
        print("ws", wheelsize)
        wheelsize = float(wheelsize)
        assert wheelsize >= 0 and wheelsize <= 100
        mult = wheelsize/8.5  # 8.5" is default
        patcher.wheel_speed_const(mult)

    thirtyamps = flask.request.form.get('thirtyamps', None)
    if thirtyamps:
        print("amp")
        patcher.ampere(30000)

    shutdown_time = flask.request.form.get('shutdown_time', None)
    if shutdown_time is not None:
        print("st", shutdown_time)
        shutdown_time = float(shutdown_time)
        assert shutdown_time >= 0 and shutdown_time <= 5
        patcher.shutdown_time(shutdown_time)

    zip_file.writestr('FIRM.bin', patcher.data)
    md5 = hashlib.md5()
    md5.update(patcher.data)

    patcher.encrypt()
    zip_file.writestr('FIRM.bin.enc', patcher.data)
    md5e = hashlib.md5()
    md5e.update(patcher.data)

    info_txt = 'dev: {};\nnam: {};\nenc: B;\ntyp: DRV;\nmd5: {};\nmd5e: {};\n'.format(
        "pro2" if version == "DRV236" else "1s", version, md5.hexdigest(), md5e.hexdigest())

    zip_file.writestr('info.txt', info_txt.encode())
    zip_file.comment = flask.request.url.encode()
    zip_file.close()
    zip_buffer.seek(0)
    content = zip_buffer.getvalue()
    zip_buffer.close()

    resp = flask.Response(content)
    filename = version + '-' + str(int(time.time())) + '.zip'
    resp.headers['Content-Type'] = 'application/zip'
    resp.headers['Content-Disposition'] = 'inline; filename="{0}"'.format(filename)
    resp.headers['Content-Length'] = len(content)

    return resp
