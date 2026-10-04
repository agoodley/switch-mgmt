"""CI: after audit -> plan -> apply -> audit against the lab, the summary must show it fixed."""

import json
import sys

summary = json.load(open(sys.argv[1]))
print(json.dumps(summary["roots"], indent=1))
assert summary["switches"] == 6 and not summary["unreachable"], summary
assert all(r["root"] == "core-01" and r["status"] == "ok" for r in summary["roots"]), summary["roots"]
assert set(summary["modes"]) == {"rapid-pvst"}, summary["modes"]
assert summary["plan"]["apply_order"] == [], summary["plan"]
print("Lab fixed: core-01 is root everywhere, all switches run rapid-pvst, nothing left to change.")
