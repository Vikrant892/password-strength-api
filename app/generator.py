import secrets
import string

# chars that look way too similar in most fonts
AMBIGUOUS_CHARS = "0O1lI|`"


def generate_password(
    length: int = 16,
    uppercase: bool = True,
    lowercase: bool = True,
    digits: bool = True,
    symbols: bool = True,
    exclude_ambiguous: bool = False,
) -> str:
    """
    generate a cryptographically secure random password
    uses secrets module (not random!) because random is not suitable for security
    """
    charset = ""

    if lowercase:
        charset += string.ascii_lowercase
    if uppercase:
        charset += string.ascii_uppercase
    if digits:
        charset += string.digits
    if symbols:
        charset += string.punctuation

    if not charset:
        # fallback if somehow everything is disabled (shouldn't happen with validation but just in case)
        charset = string.ascii_letters + string.digits

    if exclude_ambiguous:
        charset = "".join(c for c in charset if c not in AMBIGUOUS_CHARS)

    # generate and make sure we have at least one of each requested type
    # otherwise you get complaints like "where's my number??"
    while True:
        password = "".join(secrets.choice(charset) for _ in range(length))

        # verify at least one char from each requested category
        checks = []
        if lowercase:
            checks.append(any(c in string.ascii_lowercase for c in password))
        if uppercase:
            checks.append(any(c in string.ascii_uppercase for c in password))
        if digits:
            checks.append(any(c in string.digits for c in password))
        if symbols:
            checks.append(any(c in string.punctuation for c in password))

        if all(checks):
            return password
        # if we didn't get all categories, regenerate
        # with length >= 8 this almost never loops more than once
