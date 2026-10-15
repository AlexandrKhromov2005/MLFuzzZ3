#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compare fixed-input legacy and composed mutation menus with identical flags."""
import argparse
import hashlib
import json
from pathlib import Path
import statistics
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", default="186195e")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[3]
    benchmark = Path(__file__).with_name("benchmark_havoc.cpp")
    samples = {"before": [], "after": []}
    checksums = set()
    with tempfile.TemporaryDirectory(prefix="modularity-benchmark-") as directory:
        temporary = Path(directory)
        baseline = temporary / "baseline"
        for relative in ("mutators/havoc.cpp", "mutators/havoc.h", "rng.h", "mutator.h", "fuzz_input.h"):
            target = baseline / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(subprocess.check_output(
                ["git", "show", f"{args.baseline}:src/mutation/{relative}"], cwd=root))
        for name, source in (("before", baseline), ("after", root / "src/mutation")):
            subprocess.run(["c++", "-O2", "-std=c++20", "-I", str(source), str(benchmark),
                            str(source / "mutators/havoc.cpp"), "-o", str(temporary / name)], check=True)
        for repeat in range(8):
            for name in (("before", "after") if repeat % 2 == 0 else ("after", "before")):
                wall, cpu, checksum = subprocess.check_output([str(temporary / name)], text=True).split()
                samples[name].append({"wall_seconds": float(wall), "process_cpu_seconds": float(cpu)})
                checksums.add(checksum)
    if len(checksums) != 1:
        raise RuntimeError("mutation byte-stream checksums differ")
    medians = {name: {key: statistics.median(sample[key] for sample in data)
                     for key in ("wall_seconds", "process_cpu_seconds")}
               for name, data in samples.items()}
    hashes = {relative: hashlib.sha256((root / relative).read_bytes()).hexdigest()
              for relative in ("src/mutation/mutators/havoc.cpp", "src/mutation/mutators/havoc.h")}
    result = {"license": "MIT", "baseline": args.baseline, "compiler": subprocess.check_output(
        ["c++", "--version"], text=True).splitlines()[0], "flags": ["-O2", "-std=c++20"],
        "iterations_per_sample": 300000, "input_bytes": 32, "rng_seed": 1234,
        "samples": samples, "medians": medians, "checksum": next(iter(checksums)),
        "candidate_source_sha256": hashes,
        "wall_ratio": medians["after"]["wall_seconds"] / medians["before"]["wall_seconds"]}
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"medians": medians, "wall_ratio": result["wall_ratio"]}))


if __name__ == "__main__":
    main()
