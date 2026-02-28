from fastapi import HTTPException

# Define allowed lifecycle transitions
VALID_TRANSITIONS = {
    "OPEN": ["REVIEW"],
    "REVIEW": ["CLOSED"],
    "CLOSED": []
}

def validate_transition(current_status: str, new_status: str) -> None:
    """
    Validate lifecycle transition rules.

    Allowed:
        OPEN -> REVIEW
        REVIEW -> CLOSED

    Raises:
        HTTPException (400) if transition is invalid
    """

    # Extra safety: ensure current status exists in mapping
    if current_status not in VALID_TRANSITIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid current status: {current_status}"
        )

    if new_status not in VALID_TRANSITIONS[current_status]:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot move from {current_status} to {new_status}"
        )