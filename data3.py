from flask import Flask, render_template, request, jsonify, send_file

app = Flask(__name__)
wipe_system = DataWipeSystem()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/wipe', methods=['POST'])
def api_wipe():
    data = request.json
    # Web interface implementation here
    return jsonify({"status": "success"})

if __name__ == '__main__':
    app.run(debug=True)
