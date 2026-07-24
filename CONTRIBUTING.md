# Contributing to BradlyAI

Welcome! We're excited you want to help make BradlyAI — the evidence-first SOC operations platform — even better.

## 🚀 Quick Start

```bash
git clone https://github.com/sushantkane123/BradlyAI.git
cd BradlyAI
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # then edit .env with your API keys
python run.py           # → http://localhost:8000
```

## 📁 Project Structure

```
bradlyai/               # Main Python package
├── main.py             # FastAPI entrypoint, lifespan, middleware
├── config.py           # Pydantic Settings with .env support
├── database.py         # SQLAlchemy (sync + async) engine
├── models/             # SQLAlchemy ORM models
├── schemas/            # Pydantic request/response schemas
├── routers/            # Modular API routes (/api/v1/...)
├── services/           # Business logic & AI services
└── static/             # Frontend SPA (HTML/CSS/JS)
tests/                  # Pytest integration tests
```

## 🧪 Running Tests

```bash
pytest tests/ -v
pytest tests/ --cov=bradlyai --cov-report=term-missing
```

## 📝 Code Style

- **Python**: Follow [PEP 8](https://peps.python.org/pep-0008/). 4 spaces.
- **Docstrings**: Google-style for all public functions.
- **Type hints**: Use everywhere — target Python 3.11+.
- **Logging**: Use the `logging` module (no `print()` calls).

## 🔀 Pull Request Process

1. Fork the repo and create your branch from `main`
2. Write or update tests for any new functionality
3. Ensure all tests pass (`pytest tests/ -v`)
4. Update the CHANGELOG under `[Unreleased]`
5. Submit a PR with a clear description

## 📄 License

By contributing, you agree that your contributions will be licensed under the MIT License.
