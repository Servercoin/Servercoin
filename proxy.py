from flask import request, jsonify, Flask
from flask_cors import CORS
import requests
app = Flask(__name__)
url = input("URL you will use as this is a proxy to let you use gunicorn.")
CORS(app)
@app.route("/cutepuppies",methods=['POST'])
def cutepuppies():
    data = request.json
    url = data["URL"]

    newdata = requests.get(url)
    newdata = newdata.json()
    newdata = newdata["Success"]
    return jsonify({"Success":newdata})
if __name__ == "__main__":
    app.run("0.0.0.0","8001")
