import flask
import traceback
import os
import time
import io
import zipfile
import hashlib
import pathlib

from patcher import FirmwarePatcher

app = flask.Flask(__name__)
app.config["BINS"] = os.path.join(os.path.dirname(pathlib.Path(__file__).parent.absolute()), "bins")


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


@app.route('/cfw')
def patch_firmware():
    version = flask.request.args.get('version', None)
    if version not in ['DRV236', 'DRV304']:
        return 'Invalid firmware version.', 400

    with open('{}/{}.bin'.format(app.config["BINS"], version), 'rb') as fp:
        patcher = FirmwarePatcher(fp.read())

    brakelight_mod = flask.request.args.get('brakelight_mod', None)
    if brakelight_mod:
        patcher.brakelight_mod()

    speed_plus2 = flask.request.args.get('speed_plus2', None)
    if speed_plus2:
        patcher.speed_plus2()

    remove_autobrake = flask.request.args.get('remove_autobrake', None)
    if remove_autobrake:
        patcher.remove_autobrake()

    remove_kers = flask.request.args.get('remove_kers', None)
    if remove_kers:
        patcher.remove_kers()

    motor_start_speed = flask.request.args.get('motor_start_speed', None)
    if motor_start_speed is not None:
        motor_start_speed = float(motor_start_speed)
        assert motor_start_speed >= 0 and motor_start_speed <= 100
        patcher.motor_start_speed(motor_start_speed)

    remove_charging_mode = flask.request.args.get('remove_charging_mode', None)
    if remove_charging_mode:
        patcher.remove_charging_mode()


    speed_params = flask.request.args.get('speed_params', None)
    if speed_params:
        speed_ampere = int(flask.request.args.get('speed_ampere', None))
        assert speed_ampere >= 0 and speed_ampere <= 65535
        normal_ampere = int(flask.request.args.get('normal_ampere', None))
        assert normal_ampere >= 0 and normal_ampere <= 65535
        eco_ampere = int(flask.request.args.get('eco_ampere', None))
        assert eco_ampere >= 0 and eco_ampere <= 65535
        patcher.speed_params(eco_ampere, normal_ampere, speed_ampere)

    dpc = flask.request.args.get('dpc', None)
    if dpc:
        patcher.dpc_linear_register()

    # make zip file for firmware
    zip_buffer = io.BytesIO()
    zip_file = zipfile.ZipFile(zip_buffer, 'a', zipfile.ZIP_DEFLATED, False)

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
