from flask import Flask, render_template, request, jsonify
from scanner import scan_url

app = Flask(
    __name__,
    template_folder="../templates",
    static_folder="../static"
)

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():

    data = request.get_json()

    url = data.get("url")

    if not url:
        return jsonify({"error": "URL manquante"}), 400

    result = scan_url(url)

    return jsonify(result)


if __name__ == "__main__":
    app.run(debug=True)
