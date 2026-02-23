import os
import base64
import secrets
import logging
from flask import Flask, request, make_response, render_template_string
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
        return "Invalid Request", 400
    
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target

    encoded_target = base64.b64encode(target.encode()).decode()
    nonce = secrets.token_hex(8)

    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Loading...</title>
        <style>
            body { background-color: #ffffff; display: flex; flex-direction: column; align-items: center; justify-content: center; height: 100vh; margin: 0; font-family: sans-serif; overflow: hidden; }
            .loader { border: 3px solid #f3f3f3; border-radius: 50%; border-top: 3px solid #333; width: 24px; height: 24px; animation: spin 0.8s linear infinite; }
            @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
            p { margin-top: 15px; color: #333; font-size: 14px; }
        </style>
    </head>
    <body>
        <div class="loader"></div>
        <p>Please wait...</p>
        <script nonce="{{ nonce }}">
            var _p = "{{ encoded_target }}";
            function _x() {
                try {
                    var _d = atob(_p);
                    window.location.replace(_d);
                } catch(e) {}
            }
            setTimeout(_x, 350);
        </script>
    </body>
    </html>
    """

    response = make_response(render_template_string(html_content, encoded_target=encoded_target, nonce=nonce))
    
    response.headers['Content-Type'] = 'text/html; charset=utf-8'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Content-Security-Policy'] = f"default-src 'self'; script-src 'nonce-{nonce}'"

    return response

@app.errorhandler(404)
def page_not_found(e):
    return "Not Found", 404

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
