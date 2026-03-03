def calculate_confidence(score, signals):
    base = score / 100

    diversity_factor = min(len(signals) / 5, 1)

    confidence = round((base * 0.7 + diversity_factor * 0.3), 2)

    return confidence