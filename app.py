import socket
import re
from flask import Flask, request, jsonify, send_from_directory

app = Flask(__name__)

# Same ports as your original script
PORTS = {21: "FTP", 22: "SSH", 80: "HTTP", 443: "HTTPS"}
HOST_RE = re.compile(r"^[A-Za-z0-9.\-:]{1,253}$")


def scan_port(target, port):
    """Your original logic: connect_ex with a 1 second timeout."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    try:
        result = sock.connect_ex((target, port))
        return "open" if result == 0 else "closed"
    except socket.gaierror:
        return "invalid_host"
    except socket.error:
        return "unavailable"
    finally:
        sock.close()


@app.get("/")
def index():
    return send_from_directory(".", "index.html")


@app.get("/api/ports")
def ports():
    return jsonify([{"port": p, "service": s} for p, s in PORTS.items()])


@app.post("/api/scan")
def scan():
    data = request.get_json(silent=True) or {}
    host = str(data.get("host", "")).strip()
    port = data.get("port")

    if not data.get("authorized"):
        return jsonify(error="Confirm you have permission to scan this host."), 400
    if not HOST_RE.match(host):
        return jsonify(error="Invalid IP address or hostname."), 400
    if port not in PORTS:
        return jsonify(error="Port not allowed."), 400

    return jsonify(port=port, status=scan_port(host, port))


if __name__ == "__main__":
    # 127.0.0.1 keeps the scanner reachable only from your own machine
    app.run(host="127.0.0.1", port=5000, debug=False)
