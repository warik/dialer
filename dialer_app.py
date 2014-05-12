import functools
from urlparse import urljoin

import requests
import asterisk.manager
from requests_oauthlib import OAuth1
from oauthlib.oauth1 import RequestValidator, ResourceEndpoint

from flask import Flask, request, jsonify, abort

import config

app = Flask(__name__)
app.debug = config.DEBUG

class DialerRequestValidator(RequestValidator):
    enforce_ssl = False
    client_key_length = 3, 50
    access_token_length = 3, 50

    def get_client_secret(self, client_key, request):
        return None

    def get_access_token_secret(self, client_key, resource_owner_key, request):
        return unicode(config.RESOURCE_OWNER_SECRET)

    def validate_timestamp_and_nonce(self, client_key, timestamp, nonce,
            request, request_token=None, access_token=None):
        return True

    def validate_client_key(self, client_key, request):
        if client_key != 'uaprom':
            app.logger.debug('Failed on validate_client_key')
            return False
        return True

    def validate_access_token(self, client_key, token, request):
        if token != 'crm':
            app.logger.debug('Failed on validate_access_token')
            return False
        return True

    def validate_realms(self, client_key, token, request, uri=None,
            realms=None):
        return True


validator = DialerRequestValidator()
endpoint = ResourceEndpoint(validator)

def oauth_protected(realms=None):
    def wrapper(f):
        @functools.wraps(f)
        def verify_oauth(*args, **kwargs):
            app.logger.debug('Start verify request')
            app.logger.debug('request.url=%s request.method=%s request.data=%s request.headers=%s realms=%s' % (request.url, request.method, request.form or request.data, request.headers, realms))
            v, r = endpoint.validate_protected_resource_request(request.url,
                    http_method=request.method,
                    body=request.form or request.data,
                    headers=request.headers,
                    realms=realms or [])
            if v:
                return f(*args, **kwargs)
            else:
                app.logger.debug('Not valid request.')
                return abort(403)
        return verify_oauth
    return wrapper

SITES = {
    'UA': 'https://my.prom.ua/',
    'RU': 'https://my.tiu.ru/',
    'BY': 'https://my.deal.by/',
    'KZ': 'https://my.satu.kz/',
}

@app.route('/call', methods=['POST'])
@oauth_protected()
def call():
    app.logger.debug('Start call')
    inline = request.form['inline']
    exten = request.form['exten']

    channel = 'SIP/%s' % inline
    manager = asterisk.manager.Manager()
    status, error_msg, response = 'success', '', ''
    try:
        app.logger.debug('Try to connect to asterisk_address=%s and asterisk_port=%s' % (config.ASTERISK_ADDRESS, config.ASTERISK_PORT))
        manager.connect(config.ASTERISK_ADDRESS, config.ASTERISK_PORT)
        app.logger.debug('Try to login to asterisk_login=%s and asterisk_password=%s' % (config.ASTERISK_LOGIN, config.ASTERISK_PASSWORD))
        manager.login(config.ASTERISK_LOGIN, config.ASTERISK_PASSWORD)
        app.logger.debug('Try to call channel=%s and exten=%s' % (channel, exten))
        response = manager.originate(channel, exten, caller_id='call_from_CRM <CRM>', async=True).response
    except asterisk.manager.ManagerSocketException, (errno, reason):
        error_msg = 'Error connecting to the manager: %s' % reason
    except asterisk.manager.ManagerAuthException, reason:
        error_msg = 'Error logging in to the manager: %s' % reason
    except asterisk.manager.ManagerException, reason:
        error_msg = 'Error: %s' % reason
    finally:
        manager.close()
    app.logger.debug('Try to call status=%s and error=%s and response=%s' % (status, error_msg, response))
    app.logger.debug('Finish call')
    return jsonify(status=status, error=error_msg, response=response)


@app.route('/show_inuse', methods=['GET'])
@oauth_protected()
def show_inuse():
    app.logger.debug('Start show_inuse')
    manager = asterisk.manager.Manager()
    status, error_msg, response = 'success', '', ''
    try:
        manager.connect(config.ASTERISK_ADDRESS, config.ASTERISK_PORT)
        manager.login(config.ASTERISK_LOGIN, config.ASTERISK_PASSWORD)
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
    app.logger.debug('Finish show_inuse')
    return jsonify(status=status, error=error_msg, response=response)
    
@app.route('/show_channels', methods=['GET'])
@oauth_protected()
def show_channels():
    app.logger.debug('Start show_channels')
    manager = asterisk.manager.Manager()
    status, error_msg, response = 'success', '', ''
    try:
        manager.connect(config.ASTERISK_ADDRESS, config.ASTERISK_PORT)
        manager.login(config.ASTERISK_LOGIN, config.ASTERISK_PASSWORD)
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
    app.logger.debug('Finish show_channels')
    return jsonify(status=status, error=error_msg, response=response)

@app.route('/spy', methods=['POST'])
@oauth_protected()
def spy():
    app.logger.debug('Start spy')
    inline = request.form['inline']
    exten = request.form['exten']
    manager = asterisk.manager.Manager()
    status, error_msg, response = 'success', '', ''
    try:
        manager.connect(config.ASTERISK_ADDRESS, config.ASTERISK_PORT)
        manager.login(config.ASTERISK_LOGIN, config.ASTERISK_PASSWORD)
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
    app.logger.debug('Finish spy')
    return jsonify(status=status, error=error_msg, response=response)


@app.route('/queue_add', methods=['POST'])
@oauth_protected()
def queue_add():
    app.logger.debug('Start queue_add')
    queue = request.form['queue']
    interface = request.form['interface']
    state_interface = request.form['state_interface']

    manager = asterisk.manager.Manager()
    status, error_msg, response = 'success', '', ''
    try:
        manager.connect(config.ASTERISK_ADDRESS, config.ASTERISK_PORT)
        manager.login(config.ASTERISK_LOGIN, config.ASTERISK_PASSWORD)
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
    app.logger.debug('Finish queue_add')
    return jsonify(status=status, error=error_msg, response=response)

    
@app.route('/db_get', methods=['GET'])
@oauth_protected()
def db_get():
    app.logger.debug('Start db_get')
    family = request.args['family']
    key = request.args['key']
    manager = asterisk.manager.Manager()
    status, error_msg, response = 'success', '', ''
    try:
        manager.connect(config.ASTERISK_ADDRESS, config.ASTERISK_PORT)
        manager.login(config.ASTERISK_LOGIN, config.ASTERISK_PASSWORD)
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
    app.logger.debug('Finish db_get')
    return jsonify(status=status, error=error_msg, response=response)

@app.route('/queue_status', methods=['GET'])
@oauth_protected()
def queue_status():
    app.logger.debug('Start queue_status')
    manager = asterisk.manager.Manager()
    status, error_msg, response = 'success', '', ''
    try:
        manager.connect(config.ASTERISK_ADDRESS, config.ASTERISK_PORT)
        manager.login(config.ASTERISK_LOGIN, config.ASTERISK_PASSWORD)
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
    app.logger.debug('Finish queue_status')
    return jsonify(status=status, error=error_msg, response=response)

@app.route('/queue_remove', methods=['POST'])
@oauth_protected()
def queue_remove():
    app.logger.debug('Start queue_remove')
    queue = request.form['queue']
    interface = request.form['interface']
    manager = asterisk.manager.Manager()
    status, error_msg, response = 'success', '', ''
    try:
        manager.connect(config.ASTERISK_ADDRESS, config.ASTERISK_PORT)
        manager.login(config.ASTERISK_LOGIN, config.ASTERISK_PASSWORD)
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
    app.logger.debug('Finish queue_remove')
    return jsonify(status=status, error=error_msg, response=response)

### API ###
@app.route('/api/manager_phone', methods=['GET'])
def manager_phone():
    if request.remote_addr not in config.ALLOWED_HOSTS:
        abort(403)
    calling_phone = request.args['calling_phone']
    country = request.args['country'].upper()
    api_url = urljoin(SITES[country], '/agency/api/manager/manager_phone')
    payload = {'calling_phone': calling_phone}
    auth = OAuth1('dialer', resource_owner_key=config.RESOURCE_OWNER_KEY, resource_owner_secret=config.RESOURCE_OWNER_SECRET)
    response = requests.get(api_url, params=payload, auth=auth, timeout=config.API_TIMEOUT)
    if response.status_code == 200:
        return response.text
    else:
        abort(response.status_code)

@app.route('/api/manager_phone_for_company', methods=['GET'])
def manager_phone_for_company():
    if request.remote_addr not in config.ALLOWED_HOSTS:
        abort(403)
    id = request.args['id']
    country = request.args['country'].upper()
    api_url = urljoin(SITES[country], '/agency/api/manager/manager_phone_for_company')
    payload = {'id': id}
    auth = OAuth1('dialer', resource_owner_key=config.RESOURCE_OWNER_KEY, resource_owner_secret=config.RESOURCE_OWNER_SECRET)
    response = requests.get(api_url, params=payload, auth=auth, timeout=config.API_TIMEOUT)
    if response.status_code == 200:
        return response.text
    else:
        abort(response.status_code)

@app.route('/api/show_calling_popup_to_manager', methods=['GET'])
def show_calling_popup_to_manager():
    if request.remote_addr not in config.ALLOWED_HOSTS:
        abort(403)
    calling_phone = request.args['calling_phone']
    inner_number = request.args['inner_number']
    country = request.args['country'].upper()
    api_url = urljoin(SITES[country], '/agency/api/manager/show_calling_popup_to_manager')
    payload = {'calling_phone': calling_phone, 'inner_number': inner_number}
    auth = OAuth1('dialer', resource_owner_key=config.RESOURCE_OWNER_KEY, resource_owner_secret=config.RESOURCE_OWNER_SECRET)
    response = requests.get(api_url, params=payload, auth=auth, timeout=config.API_TIMEOUT)
    if response.status_code == 200:
        return response.text
    else:
        abort(response.status_code)

@app.route('/api/show_calling_review_popup_to_manager', methods=['GET'])
def show_calling_review_popup_to_manager():
    if request.remote_addr not in config.ALLOWED_HOSTS:
        abort(403)
    inner_number = request.args['inner_number']
    review_href = request.args['review_href']
    country = request.args['country'].upper()
    api_url = urljoin(SITES[country], '/agency/api/manager/show_calling_review_popup_to_manager')
    payload = {'inner_number': inner_number, 'review_href': review_href}
    auth = OAuth1('dialer', resource_owner_key=config.RESOURCE_OWNER_KEY, resource_owner_secret=config.RESOURCE_OWNER_SECRET)
    response = requests.get(api_url, params=payload, auth=auth, timeout=config.API_TIMEOUT)
    if response.status_code == 200:
        return response.text
    else:
        abort(response.status_code)

@app.route('/api/manager_call_after_hours', methods=['GET'])
def manager_call_after_hours():
    if request.remote_addr not in config.ALLOWED_HOSTS:
        abort(403)
    calling_phone = request.args['calling_phone']
    country = request.args['country'].upper()
    api_url = urljoin(SITES[country], '/agency/api/manager/manager_call_after_hours')
    payload = {'calling_phone': calling_phone}
    auth = OAuth1('dialer', resource_owner_key=config.RESOURCE_OWNER_KEY, resource_owner_secret=config.RESOURCE_OWNER_SECRET)
    response = requests.get(api_url, params=payload, auth=auth, timeout=config.API_TIMEOUT)
    if response.status_code == 200:
        return response.text
    else:
        abort(response.status_code)
