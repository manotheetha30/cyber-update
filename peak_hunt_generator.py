import json
from llm_analyzer import _ollama, _parse_json
from models import PeakHunt, PeakAct,PeakExecute,PeakPrepare
from prompts import PEAK_HUNT_PROMPT

def generate_peak_hunts(report):
    print("Executing PEAK Hunts.........")
    if not report.behaviors:
        return []

    behavior_payload = []
    for b in report.behaviors:
        behavior_payload.append(
            {
                "behavior": b.behavior,
                "evidence": b.evidence,
                "artifacts": b.artifacts,
                "context": b.context,
            }
        )

    prompt = PEAK_HUNT_PROMPT.format(
        behaviors=json.dumps(
            behavior_payload,
            indent=2,
            ensure_ascii=False,
        )
    )

    raw = _ollama(prompt,model="hunt-generator:latest")

    data = _parse_json(raw)
    hunts = []

    for hunt in data.get("peak_hunts", []):
        try:
            hunts.append(
                PeakHunt(
                    prepare=hunt["prepare"],
                    execute=hunt["execute"],
                    act=hunt["act"],
                )
            
            )
        except Exception:
            continue
    return hunts