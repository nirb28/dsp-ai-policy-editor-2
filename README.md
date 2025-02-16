# DSP AI Policy Editor

A web-based Rego policy editor with SQLite storage. This application allows users to create, edit, and test Rego policies using the OPA Playground API.

## Features

- Web-based Rego policy editor
- Policy storage in SQLite database
- Integration with OPA Playground API for policy evaluation
- Modern, responsive UI

## Setup

1. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run the application:
```bash
python app.py
```

4. Open your browser and navigate to `http://localhost:5000`

## Project Structure

- `app.py`: Main Flask application
- `models.py`: SQLite database models
- `static/`: Static files (CSS, JavaScript)
- `templates/`: HTML templates
- `instance/`: SQLite database file (auto-generated)
