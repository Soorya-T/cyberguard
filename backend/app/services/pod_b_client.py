import httpx
import os
from datetime import datetime
from httpx import HTTPError, TimeoutException

from app.core.logging import get_logger

POD_B_URL = os.getenv("POD_B_URL", "http://localhost:9999")  # Testing with wrong URL for A1

logger = get_logger(__name__)

MAX_RETRIES = 3
REQUEST_TIMEOUT = 5.0


async def analyze_with_pod_b(payload: dict):
    """
    Calls Pod B /analyze endpoint.
    Adds retry logic, timeout handling, and structured logging.
    """

    # Convert datetime fields to ISO format
    cleaned_payload = {}
    for key, value in payload.items():
        if isinstance(value, datetime):
            cleaned_payload[key] = value.isoformat()
        else:
            cleaned_payload[key] = value

    attempt = 0

    while attempt < MAX_RETRIES:
        try:
            attempt += 1

            logger.info(
                "Pod B request attempt",
                extra={
                    "attempt": attempt,
                    "endpoint": f"{POD_B_URL}/analyze"
                }
            )

            async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
                response = await client.post(
                    f"{POD_B_URL}/analyze",
                    json=cleaned_payload
                )

                response.raise_for_status()

                logger.info(
                    "Pod B request successful",
                    extra={"attempt": attempt}
                )

                return response.json()

        except TimeoutException:
            logger.warning(
                "Pod B timeout",
                extra={"attempt": attempt}
            )

        except HTTPError as e:
            logger.error(
                "Pod B HTTP error",
                extra={
                    "attempt": attempt,
                    "error": str(e)
                }
            )

        except Exception as e:
            logger.exception(
                "Pod B unexpected error",
                extra={
                    "attempt": attempt,
                    "error": str(e)
                }
            )

        if attempt >= MAX_RETRIES:
            logger.critical(
                "Pod B failed after retries",
                extra={"attempts": attempt}
            )
            raise Exception("Pod B unavailable after retries")