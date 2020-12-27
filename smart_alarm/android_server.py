#!/usr/bin/env python
"""
smart_alarm
Copyright (c) 2020, Joaquin G. Duo

Code Licensed under LGPL License. See LICENSE file.

(Works on Python 2.7 too, for old Android devices)
"""
import six
import argparse
if six.PY3:
    from http.server import HTTPServer, BaseHTTPRequestHandler
    import html
else:
    import cgi as html
    from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
import json
import pydoc

import logging
import androidhelper
import os


logger = logging.getLogger('android_server')

ANDROID_SERVER = os.environ.get('ANDROID_SERVER', '127.0.0.1')
ANDROID_SERVER_PORT = int(os.environ.get('ANDROID_SERVER_PORT', '8000'))
ANDROID_AUTH_TOKEN= os.environ.get('ANDROID_AUTH_TOKEN', '')


class Commands:
    def call_method(self, method, args=tuple(), kwargs=None):
        kwargs = kwargs or {}
        droid = androidhelper.Android()
        meth = getattr(droid, method)
        return self._to_dict(meth(*args, **kwargs))

    def __getattr__(self, name):
        droid = androidhelper.Android()
        return getattr(droid, name)

    def sms_send(self, phone, msg):
        droid = androidhelper.Android()
        r = droid.smsSend(phone, msg)
        return self._to_dict(r)

    def sms_messages(self, unread=True):
        droid = androidhelper.Android()
        return self._to_dict(droid.smsGetMessages(unread, 'inbox'))

    def _to_dict(self, result):
        return dict(id=result.id, result=result.result, error=result.error)


class CustomHandler(BaseHTTPRequestHandler):
    def _set_headers(self, code=200, content_type='application/json'):
        self.send_response(code)
        self.send_header("Content-type", content_type)
        self.end_headers()

    def _html_page(self, title, body):
        content = '<html><body><h2>'+title+'</h2>'+body+'</body></html>'
        return content.encode('utf8')

    def _docs(self):
        try:
            docshtml = pydoc.plain(pydoc.render_doc(androidhelper.Android))
            docshtml = '<pre>%s</pre>' % html.escape(docshtml)
        except Exception as e:
            print(e)
            docshtml = ''
        docs = '''<pre>
curl -d '{"method":"sms_send", "kwargs":{"phone":"2615963994"}, "auth_token":"XXX"}' -X POST http://LISTEN_ADDRESS:LISTEN_PORT/
curl -d '{"method":"sms_messages", "auth_token":"XXX"}' -X POST http://LISTEN_ADDRESS:LISTEN_PORT/
curl -d '{"method":"sms_messages", "kwargs":{"unread":false}, "auth_token":"XXX"}' -X POST http://LISTEN_ADDRESS:LISTEN_PORT/
</pre>
'''.replace('LISTEN_ADDRESS:LISTEN_PORT','%s:%s' % (ANDROID_SERVER, ANDROID_SERVER_PORT))
        return self._html_page('API Docs', docs + docshtml)

    def _send_json(self, **kwargs):
        self.wfile.write(json.dumps(kwargs).encode("utf8"))

    def _json(self, **kwargs):
        return json.dumps(kwargs).encode("utf8")

    def do_GET(self):
        if self.path != '/':
            self._set_headers(404)
            self._send_json(error='Not found')
            return
        self._set_headers(content_type='text/html')
        self.wfile.write(self._docs())

    def do_HEAD(self):
        self._set_headers()

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode('utf8')
        try:
            data = json.loads(post_data)
        except Exception as e:
            self._set_headers(500)
            self._send_json(error='Got exception %s %r' % (e, e))
        if not data.get('auth_token') == ANDROID_AUTH_TOKEN:
            self._set_headers(403)
            self._send_json(error='No auth')
        else:
            if data.get('method'):
                self._serve_method(data)
            else:
                self._set_headers(400)
                self._send_json(error='Missing args')

    def _serve_method(self, data):
        name = data.get('method')
        method = getattr(Commands(), name, None)
        if method:
            kwargs = data.get('kwargs', {})
            args = data.get('args', tuple())
            try:
                logger.info('Executing %s(*%r, **%r) %s', name, args, kwargs, method)
                json = self._json(rpc_result=method(*args, **kwargs))
                self._set_headers()
            except Exception as e:
                logger.exception('While serving %s', name)
                json = self._json(error='Executing %s got exception %s %r' % (method, e, e))
                self._set_headers(500)
            self.wfile.write(json)
        else:
            self._set_headers(400)
            self._send_json(error='No such method %r' % name)


def run(server_class=HTTPServer, handler_class=CustomHandler, addr='localhost', port=8000):
    server_address = (addr, port)
    httpd = server_class(server_address, handler_class)
    logging.info('Starting httpd server on %s:%s', addr, port)
    httpd.serve_forever()


def main():
    global ANDROID_SERVER, ANDROID_SERVER_PORT, ANDROID_AUTH_TOKEN
    logging.basicConfig()
    logging.getLogger().setLevel(logging.INFO)
    parser = argparse.ArgumentParser(description='Android HTTP server')
    parser.add_argument(
        '-l',
        '--listen',
        default=ANDROID_SERVER,
        help='IP listening address. default=%s' % ANDROID_SERVER,
    )
    parser.add_argument(
        '-p',
        '--port',
        type=int,
        default=ANDROID_SERVER_PORT,
        help='Listening port. default=%s' % ANDROID_SERVER_PORT,
    )
    parser.add_argument(
        '-t',
        '--token',
        default=ANDROID_AUTH_TOKEN,
        help='Authentication secret token',
    )
    args = parser.parse_args()
    ANDROID_SERVER = args.listen
    ANDROID_SERVER_PORT = args.port
    ANDROID_AUTH_TOKEN = args.token
    assert ANDROID_AUTH_TOKEN, 'Please specify ANDROID_AUTH_TOKEN'
    # Simple test
    _ = androidhelper.Android()
    run(addr=args.listen, port=args.port)


if __name__ == "__main__":
    main()

