import functools

from urlparse import urljoin

import asterisk.manager
import eventlet
import requests

from oauthlib.oauth1 import RequestValidator, ResourceEndpoint
from requests_oauthlib import OAuth1

from flask import Flask, request, jsonify, abort, Blueprint
from werkzeug.exceptions import RequestTimeout

import config

eventlet.monkey_patch()

app = Flask(__name__)
app.debug = config.DEBUG
manager = asterisk.manager.Manager()

ami_blueprint = Blueprint('asterisk', __name__)
api_blueprint = Blueprint('api', __name__)


class DialerRequestValidator(RequestValidator):
    enforce_ssl = False
    client_key_length = 3, 50
    access_token_length = 3, 50

    def get_client_secret(self, client_key, request):
        return None

    def get_access_token_secret(self, client_key, resource_owner_key, request):
        return unicode(config.RESOURCE_OWNER_SECRET)

    def validate_timestamp_and_nonce(
        self, client_key, timestamp, nonce, request, request_token=None, access_token=None
    ):
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

    def validate_realms(self, client_key, token, request, uri=None, realms=None):
        return True


validator = DialerRequestValidator()
endpoint = ResourceEndpoint(validator)


def oauth_protected(realms=None):
    def wrapper(f):
        @functools.wraps(f)
        def verify_oauth(*args, **kwargs):
            app.logger.debug('Start verify request')
            app.logger.debug(
                'request.url=%s request.method=%s request.data=%s request.headers=%s realms=%s' % (
                    request.url, request.method, request.form or request.data, request.headers,
                    realms
                )
            )
            v, r = endpoint.validate_protected_resource_request(
                request.url,
                http_method=request.method,
                body=request.form or request.data,
                headers=request.headers,
                realms=realms or []
            )
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


def log_action(status, error_msg, action, response):
    app.logger.debug(
        'Tried to %s status=%s and error=%s and response=%s' % (
            action, status, error_msg, response
        )
    )


def event_callback(event, manager):
    app.logger.debug('Handling event - %s' % event)
    app.logger.debug('Headers - %s' % event.headers)


@ami_blueprint.before_request
# @oauth_protected()
def before_each_dialer_request(*args, **kwargs):
    app.logger.debug('Try to connect and login to asterisk')
    status = 'success'
    response = ''

    try:
        if not manager.connected():
            manager.connect(config.ASTERISK_ADDRESS, config.ASTERISK_PORT)

        manager.login(config.ASTERISK_LOGIN, config.ASTERISK_PASSWORD)
        response = manager.send_action({
            'Action': 'Events',
            'EventMask': 'on',
        }).response
        manager.register_event('*', event_callback)
    except asterisk.manager.ManagerSocketException, (errno, reason):
        status = 'failure'
        error_msg = 'Error connecting to the manager: %s' % reason
    except asterisk.manager.ManagerAuthException, reason:
        status = 'failure'
        error_msg = 'Error login to the manager: %s' % reason
    except asterisk.manager.ManagerException, reason:
        status = 'failure'
        error_msg = 'Error: %s' % reason
    log_action(status, error_msg, 'login-connect-listen_events', response)


@ami_blueprint.after_request
def after_each_dialer_request(*args, **kwargs):
    status, action, error_msg = 'success', 'logoff', ''
    if manager.connected():
        try:
            response = manager.logoff()
        except asterisk.manager.ManagerException, reason:
            status = 'failure'
            error_msg = 'Error: %s' % reason
        log_action(status, error_msg, 'login-connect-listen_events', response)


@ami_blueprint.route('/call', methods=['POST'])
def call():
    app.logger.debug('Start call')
    inline = request.form['inline']
    exten = request.form['exten']

    channel = 'SIP/%s' % inline
    status, error_msg, response, action = 'success', '', '', 'call'
    try:
        app.logger.debug('Try to call channel=%s and exten=%s' % (channel, exten))
        response = manager.originate(
            channel, exten, caller_id='call_from_CRM <CRM>', async=True
        ).response
    except asterisk.manager.ManagerException, reason:
        error_msg = 'Error: %s' % reason

    log_action(status, error_msg, action, response)
    return jsonify(status=status, error=error_msg, response=response)


@ami_blueprint.route('/show_inuse', methods=['GET'])
def show_inuse():
    app.logger.debug('Start show_inuse')
    status, error_msg, response, action = 'success', '', '', 'show_inuse'
    try:
        response = manager.command('sip show inuse').data
    except asterisk.manager.ManagerException, reason:
        status = 'failure'
        error_msg = 'Error: %s' % reason

    log_action(status, error_msg, action, response)
    return jsonify(status=status, error=error_msg, response=response)


@ami_blueprint.route('/show_channels', methods=['GET'])
def show_channels():
    app.logger.debug('Start show_channels')
    status, error_msg, response, action = 'success', '', '', 'show_channels'
    try:
        response = manager.command('core show channels verbose').data
    except asterisk.manager.ManagerException, reason:
        status = 'failure'
        error_msg = 'Error: %s' % reason

    log_action(status, error_msg, action, response)
    return jsonify(status=status, error=error_msg, response=response)


@ami_blueprint.route('/spy', methods=['POST'])
def spy():
    app.logger.debug('Start spy')
    inline = request.form['inline']
    exten = request.form['exten']
    status, error_msg, response, action = 'success', '', '', 'spy'
    try:
        manager.send_action({
            'Action': 'Originate',
            'Channel': 'SIP/%s' % inline,
            'CallerID': 'Listening...',
            'Application': 'ChanSpy',
            'Data': 'SIP/%s,q' % exten
        }).response
    except asterisk.manager.ManagerException, reason:
        status = 'failure'
        error_msg = 'Error: %s' % reason

    log_action(status, error_msg, action, response)
    return jsonify(status=status, error=error_msg, response=response)


@ami_blueprint.route('/queue_add', methods=['POST'])
def queue_add():
    app.logger.debug('Start queue_add')
    queue = request.form['queue']
    interface = request.form['interface']
    state_interface = request.form['state_interface']
    status, error_msg, response, action = 'success', '', '', 'queue_add'
    try:
        response = manager.send_action({
            'Action': 'QueueAdd',
            'Queue': queue,
            'Interface': interface,
            'StateInterface': state_interface,
        }).response
    except asterisk.manager.ManagerException, reason:
        status = 'failure'
        error_msg = 'Error: %s' % reason

    log_action(status, error_msg, action, response)
    return jsonify(status=status, error=error_msg, response=response)


@ami_blueprint.route('/db_get', methods=['GET'])
def db_get():
    app.logger.debug('Start db_get')
    family = request.args['family']
    key = request.args['key']
    status, error_msg, response, action = 'success', '', '', 'db_get'
    try:
        response = manager.command('database get %s %s' % (family, key)).response
    except asterisk.manager.ManagerException, reason:
        status = 'failure'
        error_msg = 'Error: %s' % reason

    log_action(status, error_msg, action, response)
    return jsonify(status=status, error=error_msg, response=response)


@ami_blueprint.route('/queue_status', methods=['GET'])
def queue_status():
    app.logger.debug('Start queue_status')
    status, error_msg, response, action = 'success', '', '', 'queue_status'
    try:
        response = manager.send_action({'Action': 'QueueStatus'}).response
    except asterisk.manager.ManagerException, reason:
        status = 'failure'
        error_msg = 'Error: %s' % reason

    log_action(status, error_msg, action, response)
    return jsonify(status=status, error=error_msg, response=response)


@ami_blueprint.route('/queue_remove', methods=['POST'])
def queue_remove():
    app.logger.debug('Start queue_remove')
    queue = request.form['queue']
    interface = request.form['interface']
    status, error_msg, response, action = 'success', '', '', 'queue_remove'
    try:
        response = manager.send_action({
            'Action': 'QueueRemove',
            'Queue': queue,
            'Interface': interface,
        }).response
    except asterisk.manager.ManagerException, reason:
        status = 'failure'
        error_msg = 'Error: %s' % reason

    log_action(status, error_msg, action, response)
    return jsonify(status=status, error=error_msg, response=response)


### API ###
def try_remote_request(api_url, payload):
    auth = OAuth1(
        'dialer',
        resource_owner_key=config.RESOURCE_OWNER_KEY,
        resource_owner_secret=config.RESOURCE_OWNER_SECRET
    )
    with eventlet.Timeout(config.API_TIMEOUT, False):
        response = requests.get(api_url, params=payload, auth=auth)
        if response.status_code == 200:
            return response.text
        else:
            abort(response.status_code)
    raise RequestTimeout


@api_blueprint.before_request
def before_each_api_request(*args, **kwargs):
    if request.remote_addr not in config.ALLOWED_HOSTS:
        abort(403)


@api_blueprint.route('/manager_phone', methods=['GET'])
def manager_phone():
    calling_phone = request.args['calling_phone']
    country = request.args['country'].upper()
    api_url = urljoin(SITES[country], '/agency/api/manager/manager_phone')
    payload = {'calling_phone': calling_phone}
    return try_remote_request(api_url, payload)


@api_blueprint.route('/manager_phone_for_company', methods=['GET'])
def manager_phone_for_company():
    id = request.args['id']
    country = request.args['country'].upper()
    api_url = urljoin(SITES[country], '/agency/api/manager/manager_phone_for_company')
    payload = {'id': id}
    return try_remote_request(api_url, payload)


@api_blueprint.route('/show_calling_popup_to_manager', methods=['GET'])
def show_calling_popup_to_manager():
    calling_phone = request.args['calling_phone']
    inner_number = request.args['inner_number']
    country = request.args['country'].upper()
    api_url = urljoin(SITES[country], '/agency/api/manager/show_calling_popup_to_manager')
    payload = {'calling_phone': calling_phone, 'inner_number': inner_number}
    return try_remote_request(api_url, payload)


@api_blueprint.route('/show_calling_review_popup_to_manager', methods=['GET'])
def show_calling_review_popup_to_manager():
    inner_number = request.args['inner_number']
    review_href = request.args['review_href']
    country = request.args['country'].upper()
    api_url = urljoin(SITES[country], '/agency/api/manager/show_calling_review_popup_to_manager')
    payload = {'inner_number': inner_number, 'review_href': review_href}
    return try_remote_request(api_url, payload)


@api_blueprint.route('/manager_call_after_hours', methods=['GET'])
def manager_call_after_hours():
    calling_phone = request.args['calling_phone']
    country = request.args['country'].upper()
    api_url = urljoin(SITES[country], '/agency/api/manager/manager_call_after_hours')
    payload = {'calling_phone': calling_phone}
    return try_remote_request(api_url, payload)


app.register_blueprint(ami_blueprint)
app.register_blueprint(api_blueprint, url_prefix='/api')


if __name__ == '__main__':
    app.run(port=8000)
