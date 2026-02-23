import os
import binascii
import secrets
import logging
import random
import string
from flask import Flask, request, make_response, render_template, abort
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_compress import Compress

app = Flask(__name__)

log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

Compress(app)

limiter = Limiter(key_func=get_remote_address, app=app, default_limits=["5000 per day", "1000 per hour"])

BLOCKED_AGENTS = ['curl', 'python', 'bot', 'crawl', 'spider', 'wget', 'go-http', 'luarmor']

def hex_obfuscate(url):
    return binascii.hexlify(url.encode()).decode()

def generate_garbage(length=10):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

@app.before_request
def filter_traffic():
    ua = request.user_agent.string.lower()
    
    if "discord" in ua:
        return None

    if any(bot in ua for bot in BLOCKED_AGENTS):
        abort(500)

@app.after_request
def spoof_headers(response):
    response.headers["Server"] = "nginx/1.18.0"
    response.headers["X-Powered-By"] = "PHP/8.1.2"
    return response

@app.route('/redirect')
@limiter.limit("120 per minute")
def secure_redirect():
    target = request.args.get('verify')
    
    # UPDATED: Specific error message for missing URL
    if not target:
        return render_template('error.html', 
                             error_code="400", 
                             error_title="Bad Request", 
                             error_message="Error: Missing 'url' parameter"), 400
    
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target

    hex_target = hex_obfuscate(target)
    
    part_length = len(hex_target) // 3
    part1 = hex_target[:part_length]
    part2 = hex_target[part_length:2*part_length]
    part3 = hex_target[2*part_length:]
    
    nonce = secrets.token_hex(8)
    
    ids = {
        'container': generate_garbage(6),
        'button': generate_garbage(6),
        'loader': generate_garbage(6)
    }

    response = make_response(render_template(
        'redirect.html', 
        p1=part1, 
        p2=part2, 
        p3=part3,
        nonce=nonce,
        ids=ids
    ))
    
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Content-Security-Policy'] = f"default-src 'self'; img-src https: data:; script-src 'nonce-{nonce}' 'unsafe-eval'; style-src 'nonce-{nonce}'"

    return response

@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', error_code="404", error_title="Not Found", error_message="Resource not found"), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('error.html', error_code="500", error_title="Server Error", error_message="Internal Server Error"), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
