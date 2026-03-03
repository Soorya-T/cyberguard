import json
from app.pods.pod_b.scoring.scoring_engine import compute_risk


def run_manual_test():
    with open("app/pods/pod_b/scoring/manual_scoring_input.json", "r") as f:
        signals = json.load(f)

    result = compute_risk(signals)

    print("\n===== SCORING RESULT =====")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    run_manual_test()



