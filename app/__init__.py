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
import io


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


def patch(data):
    res = []

    patcher = FirmwarePatcher(data)

    dpc = flask.request.form.get('dpc', None)
    if dpc:
        print("dpc")
        patcher.dpc()

    relight_mod = flask.request.form.get('relight_mod', None)
    brakelight_mod = flask.request.form.get('brakelight_mod', None)
    if relight_mod:
        reset = True if flask.request.form.get('relight_reset', '') == 'on' else False
        dpc = True if flask.request.form.get('relight_dpc', '') == 'on'else False
        gm = True if flask.request.form.get('relight_gm', '') == 'on'else False
        beep = True if flask.request.form.get('relight_beep', '') == 'on'else False
        delay = True if flask.request.form.get('relight_delay', '') == 'on'else False
        if reset and not dpc and not gm:
            dpc = True
            gm = True
        opts = []
        if reset:
            opts += ["Reset"]
        if dpc:
            opts += ["DPC"]
        if gm:
            opts += ["LTGM"]
        if beep:
            opts += ["Piep"]
        if delay:
            opts += ["Delay"]
        opts = " | ".join(opts)
        res.append((f"Relight Mod: {opts}",
                    patcher.relight_mod(reset=reset, gm=gm, dpc=dpc, beep=beep, delay=delay)))
    elif brakelight_mod:
        res.append(("Bremslicht Mod", patcher.brakelight_mod()))

    speed_plus2 = flask.request.form.get('speed_plus2', None)
    if speed_plus2:
        res.append(("22 km/h Mod", patcher.speed_limit(22)))

    speed_plus2_global = flask.request.form.get('speed_plus2_global', None)
    if speed_plus2_global:
        res.append(("27 km/h Mod", patcher.speed_limit_global(27)))

    remove_autobrake = flask.request.form.get('remove_autobrake', None)
    if remove_autobrake:
        res.append(("Autom. Bremsen deaktivieren", patcher.remove_autobrake()))

    dkc = flask.request.form.get('dkc', None)
    if dkc:
        l0 = flask.request.form.get('dkc_l0', None)
        l1 = flask.request.form.get('dkc_l1', None)
        l2 = flask.request.form.get('dkc_l2', None)
        if l0 and l1 and l2:
            l0, l1, l2 = int(l0), int(l1), int(l2)
            assert l0 >= 0 and l0 <= 30
            assert l1 >= 0 and l1 <= 30
            assert l2 >= 0 and l2 <= 30
            res.append((f"D.K.C. ({l0}, {l1}, {l2})", patcher.dkc(l0, l1, l2)))

    motor_start_speed = flask.request.form.get('motor_start_speed', None)
    if motor_start_speed is not None:
        motor_start_speed = float(motor_start_speed)
        assert motor_start_speed >= 0 and motor_start_speed <= 100
        res.append((f"Motor Startgeschw. {motor_start_speed}km/h",
                    patcher.motor_start_speed(motor_start_speed)))

    remove_charging_mode = flask.request.form.get('remove_charging_mode', None)
    if remove_charging_mode:
        res.append(("Zusatzakku Fix", patcher.remove_charging_mode()))

    wheelsize = flask.request.form.get('wheelsize', None)
    if wheelsize is not None:
        wheelsize = float(wheelsize)
        assert wheelsize >= 0 and wheelsize <= 100
        mult = wheelsize/8.5  # 8.5" is default
        res.append((f"Rad Durchmesser {wheelsize}\"", patcher.wheel_speed_const(mult)))

    moreamps = flask.request.form.get('moreamps', None)
    if moreamps is not None:
        moreamps = int(moreamps)
        assert moreamps >= 20000 and moreamps <= 32000
        res.append((f"Ampere {moreamps}", patcher.ampere(moreamps)))

    shutdown_time = flask.request.form.get('shutdown_time', None)
    if shutdown_time is not None:
        shutdown_time = float(shutdown_time)
        assert shutdown_time >= 0 and shutdown_time <= 5
        res.append((f"Ausschaltzeit {shutdown_time}s",
                    patcher.shutdown_time(shutdown_time)))

    crc_1000 = flask.request.form.get('crc_1000', None)
    if crc_1000:
        res.append(("CRC 1000", patcher.current_raising_coeff(1000)))

    cc_unlock = flask.request.form.get('cc_unlock', None)
    if cc_unlock:
        res.append(("Tempomat Unlock", patcher.cc_unlock()))

    cc_delay = flask.request.form.get('cc_delay', None)
    if cc_delay is not None:
        cc_delay = float(cc_delay)
        assert cc_delay >= 0 and cc_delay <= 9
        res.append((f"Tempomat Verzögerung {cc_delay}s",
                    patcher.cc_delay(cc_delay)))

    ltgm = flask.request.form.get('ltgm', None)
    if ltgm:
        res.append(("LTGM", patcher.ltgm()))

    return res, patcher.data


@app.route('/cfw', methods=['POST'])
def patch_firmware():
    f = flask.request.files['filename']

    data = f.read()
    if not len(data) > 0xf:
        return 'Keine Datei ausgewählt.', 400

    res, data_patched = patch(data)

    pod = flask.request.form.get('patchordoc', None)
    if pod == "Patch!":
        mem = io.BytesIO()
        mem.write(data_patched)
        mem.seek(0)

        #r = flask.Response(mem, mimetype="application/octet-stream")
        #r.headers['Content-Length'] = mem.getbuffer().nbytes
        #r.headers['Content-Disposition'] = "attachment; filename={}".format(f.filename)
        return flask.send_file(
            mem,
            as_attachment=True,
            mimetype='application/octet-stream',
            attachment_filename=f.filename,
        )
    elif pod == "Offsets":
        return flask.render_template('doc.html', patches=res)
