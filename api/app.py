from flask import Flask, jsonify
import requests
import yaml

app = Flask(__name__)


@app.route('/')
def index():
    return jsonify({'message': 'truxt-dep-demo API', 'version': '1.0.0'})


@app.route('/config')
def config():
    with open('config.yaml') as f:
        cfg = yaml.safe_load(f)
    return jsonify(cfg)


if __name__ == '__main__':
    app.run(debug=True, port=5000)
