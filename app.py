import os
import base64
import secrets
import logging
from flask import Flask, request, make_response, render_template
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_compress import Compress

app = Flask(__name__)

log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

Compress(app)

limiter = Limiter(key_func=get_remote_address, app=app, default_limits=["5000 per day", "1000 per hour"])

@app.route('/redirect')
@limiter.limit("120 per minute")
def secure_redirect():
    target = request.args.get('to')
    
    if not target:
        return render_template('error.html', error_code="400", error_title="Bad Request", error_message="Error: Missing 'to' link"), 400
    
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target

    encoded_target = base64.b64encode(target.encode()).decode()
    nonce = secrets.token_hex(8)

    response = make_response(render_template('redirect.html', encoded_target=encoded_target, nonce=nonce))
    
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Content-Security-Policy'] = f"default-src 'self'; script-src 'nonce-{nonce}'"

    return response

@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', error_code="404", error_title="Not Found", error_message="The requested page does not exist"), 404

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
