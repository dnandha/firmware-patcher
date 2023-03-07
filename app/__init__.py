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
#####
# Based on https://github.com/BotoX/xiaomi-m365-firmware-patcher/blob/master/web/app.py
# Optional MYSQL and 'flask_mysql' module for click counter
#####

import flask
import traceback
import os
import io
from patcher import FirmwarePatcher, SignatureException

pwd = os.path.expanduser('~')

app = flask.Flask(__name__)

mysql = None
try:
    from flask_mysqldb import MySQL
    from conf import config

    app.config.update(config)

    mysql = MySQL(app)
except Exception as ex:
    print(ex.msg)

git_info = {
    'sha': '',
    'date': '',
    'summary': '',
}
try:
    import git
    repo = git.Repo(pwd)
    commit = repo.commit('master')
    git_info['sha'] = commit.hexsha
    git_info['date'] = commit.committed_datetime.strftime("%B %d, %Y")
    git_info['summary'] = commit.summary
except Exception as ex:
    print(ex.msg)


def save_click(pod):
    if mysql is None:
        return
    cursor = mysql.connection.cursor()
    cursor.execute('CREATE TABLE if not exists XNG(Zip int, Bin int, Doc int)')
    cursor.execute('UPDATE XNG SET '+pod+'='+pod+'+1')
    mysql.connection.commit()


def get_count(pod):
    if mysql is None:
        return 0
    cursor = mysql.connection.cursor()
    query = 'SELECT '+pod+' FROM XNG'
    cursor.execute(query)
    count = cursor.fetchall()[0][0]
    cursor.close()
    return count


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


# https://dev.to/aadibajpai/deploying-to-pythonanywhere-via-github-1j7b
@app.route('/update_server', methods=['POST'])
def webhook():
    if flask.request.method == 'POST':
        if repo:
            origin = repo.remotes.origin
            origin.pull()

            return 'Updated successfully', 200
        return 'Repo missing', 400
    else:
        return 'Wrong event type', 400


@app.route('/test')
def test():
    a = []
    while 1:
        a += ["a"]
        continue


@app.route('/')
def home():
    return flask.render_template('home.html',
                                 bincount=get_count('Bin'),
                                 zipcount=get_count('Zip'),
                                 doccount=get_count('Doc'),
                                 gitinfo=git_info)


@app.route('/privacy')
def privacy():
    return flask.render_template('privacy.html')


def patch(data):
    res = []

    patcher = FirmwarePatcher(data)

    dpc = flask.request.form.get('dpc', None)
    if dpc:
        res.append(("DPC", patcher.dpc()))

    sl_speed = flask.request.form.get('sl_speed', None)
    if sl_speed:
        sl_speed = int(sl_speed)
        assert sl_speed >= 0 and sl_speed <= 65, sl_speed
        res.append((f"Speed-Limit Sport Mode: {sl_speed}km/h", patcher.speed_limit_speed(sl_speed)))

    sl_drive = flask.request.form.get('sl_drive', None)
    if sl_drive:
        sl_drive = int(sl_drive)
        assert sl_drive >= 0 and sl_drive <= 65, sl_drive
        res.append((f"Speed-Limit Drive Mode: {sl_drive}km/h", patcher.speed_limit_drive(sl_drive)))

    sl_pedo = flask.request.form.get('sl_pedo', None)
    if sl_pedo:
        sl_pedo = int(sl_pedo)
        assert sl_pedo >= 0 and sl_pedo <= 65, sl_pedo
        res.append((f"Speed-Limit Pedestrian Mode: {sl_pedo}km/h", patcher.speed_limit_pedo(sl_pedo)))

    amps_speed = flask.request.form.get('amps_speed', None)
    if amps_speed is not None:
        amps_speed = int(amps_speed)
        assert amps_speed >= 5000 and amps_speed <= 35000, amps_speed
        res.append((f"Current Sport Mode: {amps_speed}mA", patcher.ampere_speed(amps_speed)))

    amps_drive = flask.request.form.get('amps_drive', None)
    if amps_drive is not None:
        amps_drive = int(amps_drive)
        assert amps_drive >= 5000 and amps_drive <= 35000, amps_drive
        res.append((f"Current Drive Mode: {amps_drive}mA", patcher.ampere_drive(amps_drive)))

    amps_pedo = flask.request.form.get('amps_pedo', None)
    if amps_pedo is not None:
        amps_pedo = int(amps_pedo)
        assert amps_pedo >= 5000 and amps_pedo <= 35000, amps_pedo
        res.append((f"Current Pedestrian Mode: {amps_pedo}mA", patcher.ampere_pedo(amps_pedo, 20000)))

    amps_speed_max = flask.request.form.get('amps_speed_max', None)
    amps_drive_max = flask.request.form.get('amps_drive_max', None)
    amps_pedo_max = flask.request.form.get('amps_pedo_max', None)
    if amps_speed_max is not None or amps_drive_max is not None or amps_pedo_max is not None:
        amps_speed_max = int(amps_speed_max)
        if amps_drive_max is not None:
            amps_drive_max = int(amps_drive_max)
        else:
            amps_drive_max = amps_speed_max
        amps_pedo_max = int(amps_pedo_max)
        assert amps_speed_max >= 5000 and amps_speed_max <= 65000, amps_speed_max
        assert amps_drive_max >= 5000 and amps_drive_max <= 65000, amps_drive_max
        assert amps_pedo_max >= 5000 and amps_pedo_max <= 65000, amps_pedo_max
        res.append((f"Max-Currents: {amps_pedo_max}mA/{amps_drive_max}mA/{amps_speed_max}mA",
                    patcher.ampere_max(amps_pedo_max, amps_drive_max, amps_speed_max)))

    crc = flask.request.form.get('crc', None)
    if crc:
        crc = int(crc)
        print(crc)
        assert crc >= 100 and crc <= 2000
        res.append((f"CRC: {crc}", patcher.current_raising_coeff(crc)))

    motor_start_speed = flask.request.form.get('motor_start_speed', None)
    if motor_start_speed is not None:
        motor_start_speed = float(motor_start_speed)
        assert motor_start_speed >= 0 and motor_start_speed <= 100
        res.append((f"Motor Start Speed: {motor_start_speed}km/h",
                    patcher.motor_start_speed(motor_start_speed)))

    remove_kers = flask.request.form.get('remove_kers', None)
    if remove_kers:
        res.append(("Remove KERS", patcher.remove_kers()))

    remove_autobrake = flask.request.form.get('remove_autobrake', None)
    if remove_autobrake:
        res.append(("Remove Speed Check", patcher.remove_autobrake()))

    remove_charging_mode = flask.request.form.get('remove_charging_mode', None)
    if remove_charging_mode:
        res.append(("Remove Charging Mode", patcher.remove_charging_mode()))

    wheelsize = flask.request.form.get('wheelsize', None)
    if wheelsize is not None:
        wheelsize = float(wheelsize)
        assert wheelsize >= 0 and wheelsize <= 100
        mult = wheelsize/8.5  # 8.5" is default
        res.append((f"Wheel Size: {wheelsize}\"", patcher.wheel_speed_const(mult)))

    shutdown_time = flask.request.form.get('shutdown_time', None)
    if shutdown_time is not None:
        shutdown_time = float(shutdown_time)
        assert shutdown_time >= 0 and shutdown_time <= 5
        res.append((f"Shutdown Time: {shutdown_time}s",
                    patcher.shutdown_time(shutdown_time)))

    cc_delay = flask.request.form.get('cc_delay', None)
    if cc_delay is not None:
        cc_delay = float(cc_delay)
        assert cc_delay >= 0 and cc_delay <= 9
        res.append((f"CC Delay: {cc_delay}s",
                    patcher.cc_delay(cc_delay)))

    amm = flask.request.form.get('ammeter', None)
    if amm:
        res.append(("Current-Meter", patcher.ampere_meter()))

    rfm = flask.request.form.get('rfm', None)
    if rfm:
        res.append(("Region-Free", patcher.region_free()))

    rml = flask.request.form.get('rml', None)
    if rml:
        res.append(("Remove Model Lock", patcher.remove_modellock()))

    blm = flask.request.form.get('blm', None)
    if blm:
        res.append(("Static Brakelight", patcher.brake_light()))

    alm = flask.request.form.get('blm_alm', None)
    if alm:
        res.append(("Auto-Light", patcher.lower_light()))

    baud = flask.request.form.get('baud', None)
    if baud:
        res.append(("Baudrate", patcher.bms_baudrate(76800)))

    volt = flask.request.form.get('volt', None)
    if volt is not None:
        volt = float(volt)
        assert volt >= 0 and volt <= 100
        res.append((f"Voltage Limit: {volt}V", patcher.volt_limit(volt)))

    return res, patcher.data


@app.route('/cfw', methods=['POST'])
def patch_firmware():
    f = flask.request.files['filename']

    if not f.filename.lower().endswith(".bin"):
        return "Wrong file selected.", 400

    data = f.read()
    if not len(data) > 0xf:
        return 'No file selected.', 400

    try:
        res, data_patched = patch(data)
        if not res:
            return 'No patches applied. Make sure to select the correct input file and at least one patch.'
    except SignatureException:
        return 'Some of the patches could not be applied. Please select unmodified input file.'

    dev = flask.request.form.get('device', None)
    pod = flask.request.form.get('patch', None)
    if pod in ['Bin', 'Zip']:
        filename = f.filename

        mem = io.BytesIO()
        if pod == 'Zip':
            from zip import Zippy
            params = '\n'.join([x[0] for x in res]) + '\n'
            zippy = Zippy(data_patched, params=params, model=dev)
            if not zippy.check_valid(data):
                return "Error: Invalid input file."
            data_patched = zippy.zip_it('nice'.encode())
            filename = filename[:-4] + '.zip'
        mem.write(data_patched)
        mem.seek(0)

        #r = flask.Response(mem, mimetype="application/octet-stream")
        #r.headers['Content-Length'] = mem.getbuffer().nbytes
        #r.headers['Content-Disposition'] = "attachment; filename={}".format(f.filename)
        save_click(pod)
        return flask.send_file(
            mem,
            as_attachment=True,
            mimetype='application/octet-stream',
            download_name=filename,
        )
    elif pod in ['Doc']:
        save_click(pod)
        return flask.render_template('doc.html', patches=res)
    else:
        return 'Invalid request.', 400
