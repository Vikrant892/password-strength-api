# Password Strength Analyzer API

Wanted to build something I'd actually use. Every time I create an account somewhere, I wonder if my password is actually good or if I'm just fooling myself with a capital letter and a `!` at the end.

So I built this — a FastAPI service that scores passwords on a 0-100 scale, estimates crack time, checks if they've been leaked in data breaches (via Have I Been Pwned), and can generate strong random passwords.

## What it does

- **Strength scoring** — rates passwords 0-100 based on length, character variety, entropy, common patterns (qwerty, 123456...), dictionary checks against known weak passwords, and penalties for repeated/sequential characters
- **Breach detection** — checks the Have I Been Pwned database using k-anonymity (your password never leaves your machine in full — only the first 5 chars of the SHA-1 hash are sent)
- **Password generation** — cryptographically secure random passwords with configurable length and character types
- **Demo frontend** — dark-themed UI with real-time strength meter

## Quick start

```bash
# clone and install
git clone https://github.com/Vikrant892/password-strength-api.git
cd password-strength-api
pip install -r requirements.txt

# run it
uvicorn app.main:app --reload

# open http://localhost:8000 for the demo UI
# or http://localhost:8000/docs for the Swagger docs
```

### Docker

```bash
docker build -t password-strength-api .
docker run -p 8000:8000 password-strength-api
```

## API examples

### Analyze a password

```bash
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"password": "MyP@ssw0rd!", "check_breach": true}'
```

```json
{
  "score": 62,
  "label": "strong",
  "entropy_bits": 72.08,
  "crack_time_display": "centuries",
  "suggestions": [],
  "breached": true,
  "breach_count": 12804
}
```

### Generate a strong password

```bash
curl -X POST http://localhost:8000/generate \
  -H "Content-Type: application/json" \
  -d '{"length": 20, "exclude_ambiguous": true}'
```

```json
{
  "password": "k$7Np!mR2x@Qw9Lz&4J",
  "score": 95,
  "entropy_bits": 131.09
}
```

### Health check

```bash
curl http://localhost:8000/health
```

## How the scoring works

The analyzer looks at a bunch of factors:

| Factor | Points |
|--------|--------|
| Length (8-16+) | up to 30 |
| Character variety (lower, upper, digits, symbols) | up to 32 |
| Entropy bonus | up to 20 |
| Common password match | nukes score to ≤5 |
| Keyboard patterns (qwerty, asdf...) | -10 |
| Repeated characters (aaa) | -5 to -15 |
| Sequential characters (abc, 123) | -10 |
| Same case only | -5 |

Final score is clamped to 0-100.

## How HIBP breach checking works

The API uses [Have I Been Pwned](https://haveibeenpwned.com/)'s k-anonymity model. Here's what happens:

1. Your password is SHA-1 hashed locally
2. Only the first 5 characters of the hash are sent to HIBP
3. HIBP returns all hash suffixes that match that prefix
4. We check if our full hash is in the returned list

This means HIBP never sees your password or even your full hash. Pretty clever design by Troy Hunt.

## Running tests

```bash
pytest tests/ -v
```

## Tech stack

- **FastAPI** — modern async Python web framework
- **Pydantic** — request/response validation
- **httpx** — async HTTP client for HIBP API calls
- **secrets** — stdlib module for cryptographic randomness

## TODO

- [ ] Rate limiting (don't want someone brute-forcing through this)
- [ ] Custom dictionary upload endpoint
- [ ] Zxcvbn-style pattern matching (way more sophisticated than what I have)
- [ ] Password strength history tracking
- [ ] Batch analysis endpoint
