import pytest
from app.analyzer import analyze_password, calculate_entropy
from app.generator import generate_password


class TestAnalyzer:
    """basic tests to make sure scoring isn't totally off"""

    def test_empty_password(self):
        # edge case - single char (min_length=1 in the model)
        result = analyze_password("a")
        assert result["score"] < 20
        assert result["label"] in ("very weak", "weak")

    def test_common_password_scores_low(self):
        result = analyze_password("password")
        assert result["score"] <= 10
        assert "extremely common" in result["suggestions"][0].lower()

    def test_common_password_123456(self):
        result = analyze_password("123456")
        assert result["score"] <= 10

    def test_weak_password(self):
        result = analyze_password("hello123")
        assert result["score"] < 50
        assert result["label"] in ("very weak", "weak", "moderate")

    def test_moderate_password(self):
        result = analyze_password("MyDog2024!")
        assert result["score"] >= 30
        assert result["score"] <= 80

    def test_strong_password(self):
        result = analyze_password("Tr0ub4dor&3!xK9m")
        assert result["score"] >= 60
        assert result["label"] in ("strong", "very strong")

    def test_very_strong_password(self):
        # long, mixed, no patterns - should ace it
        result = analyze_password("j$7Kp!mN2x@Qw9Lz&4R")
        assert result["score"] >= 70
        assert result["label"] in ("strong", "very strong")

    def test_keyboard_pattern_penalty(self):
        result = analyze_password("qwerty12345")
        assert result["score"] < 40

    def test_repeated_chars_penalty(self):
        result = analyze_password("aaaaaBBBBB11111")
        # lots of repeats should hurt the score
        assert result["score"] < 60

    def test_sequential_chars_penalty(self):
        result = analyze_password("abcdefghij")
        assert result["score"] < 50

    def test_all_lowercase_penalty(self):
        result = analyze_password("onlylowercase")
        suggestions = " ".join(result["suggestions"])
        assert "uppercase" in suggestions.lower() or "mix" in suggestions.lower()

    def test_entropy_increases_with_length(self):
        short = calculate_entropy("abc")
        long = calculate_entropy("abcdefghijklmnop")
        assert long > short

    def test_entropy_increases_with_variety(self):
        simple = calculate_entropy("aaaaaaa")
        varied = calculate_entropy("aA1!bB2")
        assert varied > simple

    def test_result_has_all_fields(self):
        result = analyze_password("testpassword")
        assert "score" in result
        assert "label" in result
        assert "entropy_bits" in result
        assert "crack_time_display" in result
        assert "suggestions" in result

    def test_score_in_range(self):
        # fuzz a few passwords and make sure we never go out of bounds
        passwords = ["", "a", "password", "Str0ng!Pass", "x" * 100, "!@#$%^&*"]
        for pw in passwords:
            if not pw:
                continue  # skip empty since model enforces min_length=1
            result = analyze_password(pw)
            assert 0 <= result["score"] <= 100


class TestGenerator:
    def test_generates_correct_length(self):
        pw = generate_password(length=24)
        assert len(pw) == 24

    def test_default_length(self):
        pw = generate_password()
        assert len(pw) == 16

    def test_has_all_char_types(self):
        pw = generate_password(length=20)
        assert any(c.islower() for c in pw)
        assert any(c.isupper() for c in pw)
        assert any(c.isdigit() for c in pw)
        assert any(not c.isalnum() for c in pw)

    def test_exclude_ambiguous(self):
        # generate a bunch and make sure no ambiguous chars slip through
        for _ in range(20):
            pw = generate_password(length=32, exclude_ambiguous=True)
            for c in "0O1lI|`":
                assert c not in pw

    def test_only_digits(self):
        pw = generate_password(
            length=12,
            uppercase=False,
            lowercase=False,
            digits=True,
            symbols=False,
        )
        assert pw.isdigit()
        assert len(pw) == 12

    def test_generated_password_scores_well(self):
        pw = generate_password(length=20)
        result = analyze_password(pw)
        # a 20-char random password should score pretty well
        assert result["score"] >= 50


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
