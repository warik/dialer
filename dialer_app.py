from urlparse import urljoin

import requests
import asterisk.manager
from itsdangerous import URLSafeSerializer, BadSignature

from flask import Flask, request, jsonify, abort
app = Flask(__name__)

SITES = {
    'UA': 'http://my.prom.ua/',
    'RU': 'http://my.tiu.ru/',
    'BY': 'http://my.deal.by/',
    'KZ': 'http://my.satu.kz/',
}

@app.route('/call', methods=['POST'])
def call():
    if request.form['token'] != app.config['token']:
        abort(403)

    inline = request.form['inline']
    exten = request.form['exten']

    channel = 'SIP/%s' % inline
    manager = asterisk.manager.Manager()
    status, error_msg, response = 'success', '', ''
    try:
        app.logger.debug('Try to connect to asterisk_address=%s and asterisk_port=%s' % (app.config['asterisk_address'], app.config['asterisk_port']))
        manager.connect(app.config['asterisk_address'], app.config['asterisk_port'])
        app.logger.debug('Try to login to asterisk_login=%s and asterisk_password=%s' % (app.config['asterisk_login'], app.config['asterisk_password']))
        manager.login(app.config['asterisk_login'], app.config['asterisk_password'])
        app.logger.debug('Try to call channel=%s and exten=%s' % (channel, exten))
        response = manager.originate(channel, exten, caller_id='call_from_CRM <CRM>', async=True).response
    except asterisk.manager.ManagerSocketException, (errno, reason):
        status = 'failure'
        error_msg = 'Error connecting to the manager: %s' % reason
    except asterisk.manager.ManagerAuthException, reason:
        status = 'failure'
        error_msg = 'Error logging in to the manager: %s' % reason
    except asterisk.manager.ManagerException, reason:
        status = 'failure'
        error_msg = 'Error: %s' % reason
    finally:
        manager.close()
    app.logger.debug('Try to call status=%s and error=%s and response=%s' % (status, error_msg, response))
    return jsonify(status=status, error=error_msg, response=response)


@app.route('/show_inuse', methods=['GET'])
def show_inuse():
    if request.args['token'] != app.config['token']:
        abort(403)

    manager = asterisk.manager.Manager()
    status, error_msg, response = 'success', '', ''
    try:
        manager.connect(app.config['asterisk_address'], app.config['asterisk_port'])
        manager.login(app.config['asterisk_login'], app.config['asterisk_password'])
        response = manager.command('sip show inuse').data
    except asterisk.manager.ManagerSocketException, (errno, reason):
        status = 'failure'
        error_msg = 'Error connecting to the manager: %s' % reason
    except asterisk.manager.ManagerAuthException, reason:
        status = 'failure'
        error_msg = 'Error logging in to the manager: %s' % reason
    except asterisk.manager.ManagerException, reason:
        status = 'failure'
        error_msg = 'Error: %s' % reason

    finally:
        manager.close()
    return jsonify(status=status, error=error_msg, response=response)
    
@app.route('/show_channels', methods=['GET'])
def show_channels():
    if request.args['token'] != app.config['token']:
        abort(403)

    manager = asterisk.manager.Manager()
    status, error_msg, response = 'success', '', ''
    try:
        manager.connect(app.config['asterisk_address'], app.config['asterisk_port'])
        manager.login(app.config['asterisk_login'], app.config['asterisk_password'])
        response = manager.command('core show channels verbose').data
    except asterisk.manager.ManagerSocketException, (errno, reason):
        status = 'failure'
        error_msg = 'Error connecting to the manager: %s' % reason
    except asterisk.manager.ManagerAuthException, reason:
        status = 'failure'
        error_msg = 'Error logging in to the manager: %s' % reason
    except asterisk.manager.ManagerException, reason:
        status = 'failure'
        error_msg = 'Error: %s' % reason

    finally:
        manager.close()
    return jsonify(status=status, error=error_msg, response=response)

@app.route('/spy', methods=['POST'])
def spy():
    if request.form['token'] != app.config['token']:
        abort(403)

    inline = request.form['inline']
    exten = request.form['exten']
    manager = asterisk.manager.Manager()
    status, error_msg, response = 'success', '', ''
    try:
        manager.connect(app.config['asterisk_address'], app.config['asterisk_port'])
        manager.login(app.config['asterisk_login'], app.config['asterisk_password'])
        manager.send_action({
            'Action': 'Originate',
            'Channel': 'SIP/%s' % inline,
            'CallerID': 'Listening...',
            'Application': 'ChanSpy',
            'Data': 'SIP/%s,q' % exten
        }).response
    except asterisk.manager.ManagerSocketException, (errno, reason):
        status = 'failure'
        error_msg = 'Error connecting to the manager: %s' % reason
    except asterisk.manager.ManagerAuthException, reason:
        status = 'failure'
        error_msg = 'Error logging in to the manager: %s' % reason
    except asterisk.manager.ManagerException, reason:
        status = 'failure'
        error_msg = 'Error: %s' % reason
    finally:
        manager.close()
    return jsonify(status=status, error=error_msg, response=response)


@app.route('/queue_add', methods=['POST'])
def queue_add():
    if request.form['token'] != app.config['token']:
        abort(403)

    queue = request.form['queue']
    interface = request.form['interface']
    state_interface = request.form['state_interface']

    manager = asterisk.manager.Manager()
    status, error_msg, response = 'success', '', ''
    try:
        manager.connect(app.config['asterisk_address'], app.config['asterisk_port'])
        manager.login(app.config['asterisk_login'], app.config['asterisk_password'])
        response = manager.send_action({
            'Action': 'QueueAdd',
            'Queue': queue,
            'Interface': interface,
            'StateInterface': state_interface,
        }).response
    except asterisk.manager.ManagerSocketException, (errno, reason):
        status = 'failure'
        error_msg = 'Error connecting to the manager: %s' % reason
    except asterisk.manager.ManagerAuthException, reason:
        status = 'failure'
        error_msg = 'Error logging in to the manager: %s' % reason
    except asterisk.manager.ManagerException, reason:
        status = 'failure'
        error_msg = 'Error: %s' % reason
    finally:
        manager.close()
    return jsonify(status=status, error=error_msg, response=response)

    
@app.route('/db_get', methods=['GET'])
def db_get():
    if request.args['token'] != app.config['token']:
        abort(403)

    family = request.args['family']
    key = request.args['key']
    manager = asterisk.manager.Manager()
    status, error_msg, response = 'success', '', ''
    try:
        manager.connect(app.config['asterisk_address'], app.config['asterisk_port'])
        manager.login(app.config['asterisk_login'], app.config['asterisk_password'])
        response = manager.command('database get %s %s' % (family, key)).response
    except asterisk.manager.ManagerSocketException, (errno, reason):
        status = 'failure'
        error_msg = 'Error connecting to the manager: %s' % reason
    except asterisk.manager.ManagerAuthException, reason:
        status = 'failure'
        error_msg = 'Error logging in to the manager: %s' % reason
    except asterisk.manager.ManagerException, reason:
        status = 'failure'
        error_msg = 'Error: %s' % reason

    finally:
        manager.close()
    return jsonify(status=status, error=error_msg, response=response)

@app.route('/queue_status', methods=['GET'])
def queue_status():
    if request.args['token'] != app.config['token']:
        abort(403)

    manager = asterisk.manager.Manager()
    status, error_msg, response = 'success', '', ''
    try:
        manager.connect(app.config['asterisk_address'], app.config['asterisk_port'])
        manager.login(app.config['asterisk_login'], app.config['asterisk_password'])
        response = manager.send_action({
            'Action': 'QueueStatus',
        }).response
    except asterisk.manager.ManagerSocketException, (errno, reason):
        status = 'failure'
        error_msg = 'Error connecting to the manager: %s' % reason
    except asterisk.manager.ManagerAuthException, reason:
        status = 'failure'
        error_msg = 'Error logging in to the manager: %s' % reason
    except asterisk.manager.ManagerException, reason:
        status = 'failure'
        error_msg = 'Error: %s' % reason

    finally:
        manager.close()
    return jsonify(status=status, error=error_msg, response=response)

@app.route('/queue_remove', methods=['POST'])
def queue_remove():
    if request.form['token'] != app.config['token']:
        abort(403)
    queue = request.form['queue']
    interface = request.form['interface']
    manager = asterisk.manager.Manager()
    status, error_msg, response = 'success', '', ''
    try:
        manager.connect(app.config['asterisk_address'], app.config['asterisk_port'])
        manager.login(app.config['asterisk_login'], app.config['asterisk_password'])
        response = manager.send_action({
            'Action': 'QueueRemove',
            'Queue': queue,
            'Interface': interface,
        }).response
    except asterisk.manager.ManagerSocketException, (errno, reason):
        status = 'failure'
        error_msg = 'Error connecting to the manager: %s' % reason
    except asterisk.manager.ManagerAuthException, reason:
        status = 'failure'
        error_msg = 'Error logging in to the manager: %s' % reason
    except asterisk.manager.ManagerException, reason:
        status = 'failure'
        error_msg = 'Error: %s' % reason
    finally:
        manager.close()
    return jsonify(status=status, error=error_msg, response=response)


@app.route('/manager_phone', methods=['GET'])
def manager_phone():
    if request.args['token'] != app.config['token']:
        abort(403)
    calling_phone = request.args['calling_phone']
    country = request.args['country'].upper()
    api_url = urljoin(SITES[country], '/agency/api/manager/manager_phone')
    payload = {'calling_phone': calling_phone, 'token': app.config['token']}
    response = requests.get(api_url, params=payload)
    if response.status_code == 200:
        return response.text
    else:
        abort(response.status_code)

@app.route('/manager_phone_for_company', methods=['GET'])
def manager_phone_for_company():
    if request.args['token'] != app.config['token']:
        abort(403)
    id = request.args['id']
    country = request.args['country'].upper()
    api_url = urljoin(SITES[country], '/agency/api/manager/manager_phone_for_company')
    payload = {'id': id, 'token': app.config['token']}
    response = requests.get(api_url, params=payload)
    if response.status_code == 200:
        return response.text
    else:
        abort(response.status_code)

@app.route('/show_calling_popup_to_manager', methods=['GET'])
def show_calling_popup_to_manager():
    if request.args['token'] != app.config['token']:
        abort(403)
    calling_phone = request.args['calling_phone']
    inner_number = request.args['inner_number']
    country = request.args['country'].upper()
    api_url = urljoin(SITES[country], '/agency/api/manager/show_calling_popup_to_manager')
    payload = {'calling_phone': calling_phone, 'inner_number': inner_number, 'token': app.config['token']}
    response = requests.get(api_url, params=payload)
    if response.status_code == 200:
        return response.text
    else:
        abort(response.status_code)

@app.route('/show_calling_review_popup_to_manager', methods=['GET'])
def show_calling_review_popup_to_manager():
    if request.args['token'] != app.config['token']:
        abort(403)
    inner_number = request.args['inner_number']
    review_href = request.args['review_href']
    country = request.args['country'].upper()
    api_url = urljoin(SITES[country], '/agency/api/manager/show_calling_review_popup_to_manager')
    payload = {'inner_number': inner_number, 'review_href': review_href, 'token': app.config['token']}
    response = requests.get(api_url, params=payload)
    if response.status_code == 200:
        return response.text
    else:
        abort(response.status_code)

@app.route('/manager_call_after_hours', methods=['GET'])
def manager_call_after_hours():
    if request.args['token'] != app.config['token']:
        abort(403)
    calling_phone = request.args['calling_phone']
    country = request.args['country'].upper()
    api_url = urljoin(SITES[country], '/agency/api/manager/manager_call_after_hours')
    payload = {'calling_phone': calling_phone, 'token': app.config['token']}
    response = requests.get(api_url, params=payload)
    if response.status_code == 200:
        return response.text
    else:
        abort(response.status_code)

def main(global_config, **local_config):
    from paste.util.converters import asbool

    conf = dict(global_config, **local_config)

    app.config.update(
        asterisk_address=conf.get('asterisk.address'),
        asterisk_port=conf.get('asterisk.port'),
        asterisk_login=conf.get('asterisk.login'),
        asterisk_password=conf.get('asterisk.password'),
        token=conf.get('token')
    )
    app.debug = asbool(conf.get('debug'))

    return app
