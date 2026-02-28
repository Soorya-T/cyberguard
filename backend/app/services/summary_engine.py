def generate_summary(score, verdict, signals):
    count = len(signals)

    if verdict == "CRITICAL":
        level = "severe and requires immediate containment."
    elif verdict == "HIGH":
        level = "high risk and should be investigated promptly."
    elif verdict == "MEDIUM":
        level = "moderate risk and requires verification."
    else:
        level = "minimal risk based on current analysis."

    return (
        f"The analyzed email triggered {count} threat indicators. "
        f"Overall risk score is {score}. "
        f"The threat level is classified as {verdict}, which indicates the email is {level}"
    )