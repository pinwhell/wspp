import json
import sys
from pathlib import Path

OK_BEHAVIORS = {"OK", "UNIMPLEMENTED", "NON-STRICT"}

def check_index(path):
    data = json.loads(Path(path).read_text())
    impl = next(iter(data.values()))

    for case, result in impl.items():
        b = result.get("behavior")
        bc = result.get("behaviorClose")

        if b not in OK_BEHAVIORS:
            print(f"FAIL: {path} case {case} behavior={b}")
            return False

        if bc != "OK":
            print(f"FAIL: {path} case {case} behaviorClose={bc}")
            return False

    return True


paths = [
    "reports/wspp-client/index.json",
    "reports/wspp-server/index.json",
]

for p in paths:
    if not Path(p).exists():
        print(f"Missing {p}")
        sys.exit(1)

    if not check_index(p):
        sys.exit(1)

print("Autobahn JSON validation passed")
