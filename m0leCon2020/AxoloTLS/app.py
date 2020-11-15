from flask import Flask, request, render_template, send_file, jsonify, abort
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes

import io
from PIL import Image
import base64
import os
import random

app = Flask(__name__)
CIPHER_KEY = b'\xefF~\xa4=*\xcf\xd7vm\x1b\t;#\xaf8'
DH_KEY = int(os.getenv("DH_KEY"))
DH_P = int(os.getenv("DH_P"))


def get_key_from_dh(pub):
    shared = pow(pub, DH_KEY, DH_P)
    key = long_to_bytes(shared)[-16:]
    key = b"\x00" * (16 - len(key)) + key
    assert len(key) == 16
    return key


def check_filetype_from_bytes(bb):
    imageStream = io.BytesIO(bb)
    img = Image.open(imageStream)
    return img.format


@app.route("/")
def index():
    filename = request.args.get('filename')
    if filename is None:
        images = os.listdir("images/public")
        filename = random.choice(images)

    return render_template("index.html", filename=filename)


@app.route("/dh")
def dh():
    pub = pow(2, DH_KEY, DH_P)
    return jsonify(p=DH_P, x=pub)


@app.route("/upload", methods=["POST"])
def upload():
    try:
        res = request.get_json()
        ciphertext = base64.b64decode(res["enc_image"])
        tag = base64.b64decode(res["tag"])
        nonce = base64.b64decode(res["nonce"])
        pub = int(res["pub"])
        filename = os.path.split(res["filename"])[1]
        # decrypt
        sh_key = get_key_from_dh(pub)
        cipher = AES.new(sh_key, AES.MODE_GCM, nonce=nonce)
        ciphertxt = cipher.decrypt_and_verify(ciphertext, tag)
        my_key = CIPHER_KEY
        cipher = AES.new(my_key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        # check if image
        ft = check_filetype_from_bytes(plaintext)
        if ft in ["PNG", "JPG", "JPEG"] and len(plaintext) < 102400:
            with open("images/public/"+filename, "wb") as f:
                f.write(plaintext)
        else:
            return "Send a real image less than 100kb!"
    except:
        abort(400)

    # Thank you for your image, here's my favourite one!
    return send_file("images/private/best_axolotl.png", mimetype="image/png")


if __name__ == "__main__":
    app.run()
