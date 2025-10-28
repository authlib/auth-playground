import os

from dotenv import load_dotenv

from auth_playground import create_app


def run():
    """Run the Auth Playground application."""
    load_dotenv()
    app = create_app()
    host = os.environ.get("FLASK_RUN_HOST", "0.0.0.0")
    port = int(os.environ.get("FLASK_RUN_PORT", "4000"))
    debug = os.environ.get("FLASK_DEBUG", "True").lower() == "true"
    app.run(host=host, port=port, debug=debug)


if __name__ == "__main__":
    run()
