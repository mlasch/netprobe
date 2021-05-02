import http

from flask import Flask
from flask import request

app = Flask(__name__)


@app.route('/')
def hello_world():
    return 'Mock server'


@app.route("/write/<token>", methods=["POST"])
def write(token):
    print(token)

    for key, value in request.form.items():
        line = key+"="+value
        print(line.split(",", 1))

    return '', http.HTTPStatus.NO_CONTENT


if __name__ == '__main__':
    app.run(debug=True)
