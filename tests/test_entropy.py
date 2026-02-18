from aminscan.entropy import shannon_entropy, looks_like_high_entropy_token

def test_entropy_basic():
    assert shannon_entropy("aaaaaaaaaa") < 1.0
    assert shannon_entropy("abcd1234ABCD5678") > 2.0

def test_high_entropy_token_heuristic():
    # This is a random-looking string but NOT a real provider token format
    s = "R4nd0m_Str1ng_WithLotsOfVariety_1234567890+=="
    assert looks_like_high_entropy_token(s) is True

    low = "this_is_not_random_at_all________"
    assert looks_like_high_entropy_token(low) is False
