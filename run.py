"""Start the integrated dashboard from the repository root."""
import argparse
from pipeline import FRAMEWORK_DIR
from app import app

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Android APK risk analysis dashboard')
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=5000)
    args = parser.parse_args()
    app.run(host=args.host, port=args.port, debug=False)
