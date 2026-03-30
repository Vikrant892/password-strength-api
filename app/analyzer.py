import math
import re
import string

# top common passwords - grabbed the usual suspects from various leaked lists
# not the full 10k list but enough to catch the obvious ones
COMMON_PASSWORDS = {
    "password", "123456", "123456789", "12345678", "12345", "1234567",
    "1234567890", "qwerty", "abc123", "111111", "password1", "iloveyou",
    "1q2w3e4r", "000000", "qwerty123", "zaq12wsx", "dragon", "sunshine",
    "princess", "letmein", "654321", "monkey", "27653", "1qaz2wsx",
    "123321", "qwertyuiop", "superman", "asdfghjkl", "trustno1",
    "bazinga", "batman", "football", "shadow", "master", "michael",
    "baseball", "access", "hello", "charlie", "donald", "password123",
    "admin", "welcome", "login", "starwars", "solo", "whatever",
    "passw0rd", "summer", "spring", "autumn", "winter", "cheese",
    "corvette", "cookie", "richard", "ranger", "striker", "hunter",
    "buster", "soccer", "harley", "andrew", "tigger", "joshua",
    "pepper", "george", "matrix", "yankees", "thunder", "taylor",
    "austin", "merlin", "ginger", "robert", "bailey", "testing",
    "hockey", "dallas", "jordan", "thomas", "compaq", "internet",
    "mustang", "golfer", "chicken", "maverick", "secret", "fucker",
    "computer", "jennifer", "jessica", "banana", "1234", "abcdef",
    "qazwsx", "ashley", "killer", "diamond", "maggie", "nicole",
    "daniel", "andrea", "spider", "junior", "nathan", "orange",
    "winner", "mother", "hannah", "jasmine", "peanut", "london",
    "abcdefg", "freedom", "william", "samantha", "lovers", "phoenix",
    "chelsea", "biteme", "amanda", "melissa", "midnight", "anthony",
}

# keyboard sequences people love to use
KEYBOARD_PATTERNS = [
    "qwerty", "qwertz", "azerty", "asdf", "zxcv", "wasd",
    "1234", "2345", "3456", "4567", "5678", "6789", "7890",
    "abcd", "bcde", "cdef", "defg",
    "!@#$", "@#$%", "#$%^",
]


def calculate_entropy(password: str) -> float:
    """
    entropy calc - had to look this up
    basically log2(charset_size ^ length)
    which simplifies to length * log2(charset_size)
    """
    charset_size = 0

    if any(c in string.ascii_lowercase for c in password):
        charset_size += 26
    if any(c in string.ascii_uppercase for c in password):
        charset_size += 26
    if any(c in string.digits for c in password):
        charset_size += 10
    if any(c in string.punctuation for c in password):
        charset_size += 32

    if charset_size == 0:
        # unicode or something weird, just estimate
        charset_size = 128

    return len(password) * math.log2(charset_size)


def estimate_crack_time(entropy_bits: float) -> str:
    """
    rough estimate assuming 10 billion guesses/sec (decent GPU rig)
    this is hand-wavy but gives users a ballpark idea
    """
    guesses = 2 ** entropy_bits
    seconds = guesses / 10_000_000_000  # 10B guesses/sec

    if seconds < 0.001:
        return "instantly"
    elif seconds < 1:
        return "less than a second"
    elif seconds < 60:
        return f"{int(seconds)} seconds"
    elif seconds < 3600:
        return f"{int(seconds / 60)} minutes"
    elif seconds < 86400:
        return f"{int(seconds / 3600)} hours"
    elif seconds < 86400 * 365:
        return f"{int(seconds / 86400)} days"
    elif seconds < 86400 * 365 * 1000:
        return f"{int(seconds / (86400 * 365))} years"
    elif seconds < 86400 * 365 * 1_000_000:
        return f"{int(seconds / (86400 * 365 * 1000))}k years"
    else:
        return "centuries"


def analyze_password(password: str) -> dict:
    score = 0
    suggestions = []

    # --- length scoring (biggest factor honestly) ---
    length = len(password)
    if length >= 16:
        score += 30
    elif length >= 12:
        score += 22
    elif length >= 10:
        score += 15
    elif length >= 8:
        score += 10
    else:
        score += 3
        suggestions.append("Use at least 8 characters, 12+ is better")

    # --- character variety ---
    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_symbol = bool(re.search(r"[^a-zA-Z0-9]", password))

    variety_count = sum([has_lower, has_upper, has_digit, has_symbol])
    score += variety_count * 8  # up to 32 points

    if not has_upper:
        suggestions.append("Add uppercase letters")
    if not has_lower:
        suggestions.append("Add lowercase letters")
    if not has_digit:
        suggestions.append("Add numbers")
    if not has_symbol:
        suggestions.append("Add special characters (!@#$%...)")

    # --- common password check ---
    if password.lower() in COMMON_PASSWORDS:
        score = min(score, 5)  # nuke the score
        suggestions.insert(0, "This is an extremely common password - change it immediately")

    # --- keyboard patterns ---
    lower_pw = password.lower()
    for pattern in KEYBOARD_PATTERNS:
        if pattern in lower_pw:
            score -= 10
            suggestions.append(f"Avoid keyboard patterns like '{pattern}'")
            break  # only penalize once

    # --- sequential characters (aaa, 111, etc) ---
    max_repeat = 1
    current_repeat = 1
    for i in range(1, len(password)):
        if password[i] == password[i - 1]:
            current_repeat += 1
            max_repeat = max(max_repeat, current_repeat)
        else:
            current_repeat = 1

    if max_repeat >= 3:
        score -= 15
        suggestions.append("Avoid repeating characters (aaa, 111)")
    elif max_repeat >= 2:
        score -= 5

    # --- sequential runs (abc, 123, etc) ---
    sequential_count = 0
    for i in range(2, len(password)):
        if (ord(password[i]) == ord(password[i-1]) + 1 and
                ord(password[i-1]) == ord(password[i-2]) + 1):
            sequential_count += 1

    if sequential_count >= 2:
        score -= 10
        suggestions.append("Avoid sequential characters (abc, 123)")

    # --- all same case penalty ---
    if password.isalpha() and (password.islower() or password.isupper()):
        score -= 5
        suggestions.append("Mix uppercase and lowercase letters")

    # --- entropy ---
    entropy_bits = calculate_entropy(password)

    # entropy bonus (rewards truly random passwords)
    if entropy_bits >= 60:
        score += 20
    elif entropy_bits >= 45:
        score += 12
    elif entropy_bits >= 30:
        score += 5

    # clamp to 0-100
    score = max(0, min(100, score))

    # figure out the label
    if score >= 80:
        label = "very strong"
    elif score >= 60:
        label = "strong"
    elif score >= 40:
        label = "moderate"
    elif score >= 20:
        label = "weak"
    else:
        label = "very weak"

    crack_time = estimate_crack_time(entropy_bits)

    return {
        "score": score,
        "label": label,
        "entropy_bits": round(entropy_bits, 2),
        "crack_time_display": crack_time,
        "suggestions": suggestions,
    }
