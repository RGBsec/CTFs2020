import base64
import logging
import os
import re

from flask import Flask, render_template, request, flash, abort
from flask_bootstrap import Bootstrap
from werkzeug.exceptions import Forbidden

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = './uploads'
app.config['SECRET_KEY'] = '********************'
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024  # 500Kb
Bootstrap(app)
logging.getLogger().setLevel(logging.DEBUG)

secret_key = [c for c in open("secret.key", "rb").read()]
MSIZE = len(secret_key)
assert MSIZE == 12


def xor(a, b):
    return list(map(lambda x: x[0] ^ x[1], zip(a, b)))


@app.route('/', methods=['GET', 'POST'])
def index():
    try:
        logging.debug(request.headers)
        if request.method == 'POST':
            message = request.form.get("message", "")
            rb_init = os.urandom(MSIZE)
            flash(f'{base64.b64encode(rb_init).decode()}', 'success')

            rb = bytearray(xor(rb_init, secret_key))
            rb64 = base64.b64encode(rb).decode()
            with open('static/' + rb64, 'w') as w:
                w.write(message)

    except Exception as e:
        logging.error(e)

    return render_template("index.html")


@app.route('/get', methods=["POST"])
def get():
    logging.debug(request.headers)
    try:
        fileid = request.form.get("fileid")
        logging.debug(fileid)
        if not re.match("^[a-zA-Z0-9/+]{16}$", fileid) or "admin" in fileid:
            return abort(403)
        rb = bytearray(xor(base64.b64decode(fileid), secret_key))
        rb64 = base64.b64encode(rb).decode()
        data = open('static/' + rb64).read()
        return data
    except Forbidden:
        return abort(403)
    except Exception as e:
        logging.error(e)
        return abort(404)


if __name__ == "__main__":
    app.run(host='localhost', port=5000)
