import os  # pragma: no cover

from dotenv import load_dotenv  # pragma: no cover

from auth_playground import create_app  # pragma: no cover


def run():  # pragma: no cover
    """Run the Auth Playground application."""
    load_dotenv()
    app = create_app()
    host = os.environ.get("FLASK_RUN_HOST", "0.0.0.0")
    port = int(os.environ.get("FLASK_RUN_PORT", "4000"))
    debug = os.environ.get("FLASK_DEBUG", "True").lower() == "true"
    app.run(host=host, port=port, debug=debug)


if __name__ == "__main__":  # pragma: no cover
    run()
