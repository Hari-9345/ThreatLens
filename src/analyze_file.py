import json
import sys
from pathlib import Path

from detector import analyze_event


def main():
    if len(sys.argv) != 3:
        print("Usage: python src\\analyze_file.py <input.json> <output.json>")
        sys.exit(1)

    input_file = Path(sys.argv[1])
    output_file = Path(sys.argv[2])

    if not input_file.exists():
        print(f"[ERROR] Input file not found: {input_file}")
        sys.exit(1)

    try:
        with input_file.open("r", encoding="utf-8-sig") as file:
            events = json.load(file)

        if not isinstance(events, list):
            raise ValueError("Expected a JSON list of process events.")

        results = [analyze_event(event) for event in events]

        output_file.parent.mkdir(parents=True, exist_ok=True)

        with output_file.open("w", encoding="utf-8") as file:
            json.dump(results, file, indent=4)

        flagged = sum(
            1 for result in results
            if result["status"] == "FLAGGED"
        )

        print("[SUCCESS] Analysis completed.")
        print(f"[INPUT] {input_file}")
        print(f"[TOTAL EVENTS] {len(results)}")
        print(f"[FLAGGED] {flagged}")
        print(f"[NORMAL] {len(results) - flagged}")
        print(f"[OUTPUT] {output_file}")

    except (json.JSONDecodeError, ValueError, OSError) as error:
        print(f"[ERROR] {error}")
        sys.exit(1)


if __name__ == "__main__":
    main()
