
from flask import request, jsonify, Flask
from flask_cors import CORS
import requests
app = Flask(__name__)
url = input("URL you will use as this is a proxy to let you use gunicorn.")
CORS(app)
@app.route("/<path:path>",methods=['GET'])
def cutepuppies(path):
    
    print("PAth: "+str(path))
    newdata = requests.get(url+"/"+path)
    newdata = newdata.json()
    newdata = newdata["Success"]
    return jsonify({"Success":newdata})
if __name__ == "__main__":
    app.run("0.0.0.0","8001")
