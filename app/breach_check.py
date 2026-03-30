import hashlib
import httpx

# hibp uses k-anonymity which is clever
# you send the first 5 chars of the SHA-1 hash, they send back all matching suffixes
# so they never see the actual password or even the full hash
# pretty elegant for a security API

HIBP_API_URL = "https://api.pwnedpasswords.com/range/"


async def check_breach(password: str) -> dict:
    """
    check if password has appeared in known data breaches
    uses the HIBP k-anonymity model so the password never leaves your machine in full
    """
    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{HIBP_API_URL}{prefix}",
                headers={"User-Agent": "password-strength-api/0.1"},
                timeout=5.0,
            )

        if response.status_code != 200:
            # don't fail the whole request just because HIBP is down
            return {"breached": None, "breach_count": None}

        # response is lines of "SUFFIX:COUNT"
        for line in response.text.splitlines():
            hash_suffix, count = line.split(":")
            if hash_suffix == suffix:
                return {"breached": True, "breach_count": int(count)}

        return {"breached": False, "breach_count": 0}

    except (httpx.RequestError, httpx.TimeoutException):
        # network issues shouldn't break the analyzer
        # TODO: maybe add retry logic later? or at least log this
        return {"breached": None, "breach_count": None}
