from app import create_app

app = create_app()

if __name__ == "__main__":
    # Port 5000 = the VULNERABLE build
    app.run(host="127.0.0.1", port=5000, debug=True)
