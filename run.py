import os

from app import create_app

app = create_app()

if __name__ == "__main__":
    # Debug mode is OFF by default (the Werkzeug debugger allows code
    # execution). Enable locally with: FLASK_DEBUG=1 python run.py
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
