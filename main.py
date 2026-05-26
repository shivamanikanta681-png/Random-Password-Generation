from flask import Flask, jsonify, request

from src.generator import PasswordGenerationError
from src.web import HTML, generate_payload


app = Flask(__name__)


@app.get("/")
def home():
    return HTML


@app.get("/api/generate")
def generate():
    try:
        return jsonify(generate_payload(request.args))
    except (PasswordGenerationError, ValueError) as error:
        return jsonify({"error": str(error)}), 400


handler = app


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, debug=True)
