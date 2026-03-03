import sys
import traceback
from app.pods.pod_b.services.verdict_service import VerdictService

vs = VerdictService()
data = {
    'sender': 'attacker@fake-bank.com',
    'subject': 'URGENT: Verify your account',
    'body': 'Click here immediately to verify your bank account.',
    'links': []
}

try:
    result = vs.analyze(data)
    print('Result:', result, file=sys.stdout)
except Exception as e:
    print('Error:', str(e), file=sys.stderr)
    traceback.print_exc(file=sys.stderr)
