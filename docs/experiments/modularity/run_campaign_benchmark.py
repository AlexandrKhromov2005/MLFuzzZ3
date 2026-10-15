#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Measure the Debug controller and journal separately using configured libraries."""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import statistics
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", default="186195e")
    parser.add_argument("--build-dir", type=Path, default=Path("build"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[3]
    build = args.build_dir.resolve()
    database = json.loads((build / "compile_commands.json").read_text())
    entry = next(row for row in database if row["file"].endswith("/unit/core/test_campaign.cpp"))
    compile_command = shlex.split(entry["command"])
    compiler = compile_command[0]
    flags = []
    index = 1
    while index < len(compile_command):
        token = compile_command[index]
        if token == "-o":
            index += 2
        elif token == "-c":
            index += 1
        elif token == entry["file"]:
            index += 1
        else:
            flags.append(token)
            index += 1
    implementation = next(row for row in database if row["file"].endswith("/src/core/campaign.cpp"))
    extra = shlex.split(implementation["command"])[1:]
    index = 0
    while index < len(extra):
        if extra[index] == "-o":
            index += 2
        elif extra[index] == "-c" or extra[index] == implementation["file"]:
            index += 1
        else:
            flags.append(extra[index])
            index += 1
    raw_link = subprocess.check_output(
        ["ninja", "-C", str(build), "-t", "commands", "test_campaign"], text=True).splitlines()[-1]
    tokens = shlex.split(raw_link)
    tokens = tokens[tokens.index("&&") + 1:]
    tokens = tokens[:tokens.index("&&")]
    link = []
    index = 0
    while index < len(tokens):
        if tokens[index] == "-o":
            index += 2
        elif tokens[index].endswith(".o"):
            index += 1
        else:
            link.append(tokens[index])
            index += 1
    samples = {name: [] for name in ("before", "after", "journal")}
    checksums = set()
    source = Path(__file__).with_name("benchmark_campaign.cpp")
    with tempfile.TemporaryDirectory(prefix="modularity-controller-benchmark-") as directory:
        temporary = Path(directory)
        old = temporary / "baseline"
        paths = subprocess.check_output(["git", "ls-tree", "-r", "--name-only", args.baseline,
                                         "src/core", "src/mutation"], cwd=root, text=True).splitlines()
        for relative in paths:
            if relative.endswith(".h") or relative in ("src/core/campaign.cpp", "src/mutation/mutators/havoc.cpp"):
                target = old / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(subprocess.check_output(
                    ["git", "show", f"{args.baseline}:{relative}"], cwd=root))
        binaries = {}
        for name in ("before", "after"):
            local_flags = (["-I" + str(old / "src/core"), "-I" + str(old / "src/mutation")]
                           if name == "before" else ["-DMODULAR_BENCHMARK"])
            sources = [source]
            if name == "before":
                sources += [old / "src/core/campaign.cpp", old / "src/mutation/mutators/havoc.cpp"]
            objects = []
            for number, unit in enumerate(sources):
                obj = temporary / f"{name}-{number}.o"
                subprocess.run([compiler, *local_flags, *flags, "-c", str(unit), "-o", str(obj)],
                               cwd=build, check=True)
                objects.append(str(obj))
            binary = temporary / name
            subprocess.run([*link[:1], *objects, *link[1:], "-o", str(binary)], cwd=build, check=True)
            binaries[name] = binary
        for repeat in range(6):
            order = ("before", "after", "journal") if repeat % 2 == 0 else ("journal", "after", "before")
            for name in order:
                output = temporary / f"run-{repeat}-{name}"
                binary = binaries["after" if name == "journal" else name]
                wall, cpu, checksum, executed = subprocess.check_output(
                    [str(binary), str(output), name], text=True).split()
                if int(executed) != 100000:
                    raise RuntimeError("execution count differs")
                checksums.add(checksum)
                journal = output / "events.jsonl"
                samples[name].append({"wall_seconds": float(wall), "process_cpu_seconds": float(cpu),
                                      "journal_bytes": journal.stat().st_size if journal.exists() else 0})
                # Only this script's generated run directories are removed by TemporaryDirectory.
        if len(checksums) != 1:
            raise RuntimeError("executed byte-stream checksums differ")
    medians = {name: {key: statistics.median(sample[key] for sample in values)
                     for key in ("wall_seconds", "process_cpu_seconds", "journal_bytes")}
               for name, values in samples.items()}
    source_files = sorted(p for folder in ("src/core", "src/composition", "src/mutation")
                          for p in (root / folder).rglob("*") if p.suffix in (".cpp", ".h"))
    hashes = {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in source_files}
    result = {"license": "MIT", "baseline": args.baseline, "build_type": "Debug", "compile_flags": flags,
              "iterations_per_sample": 100000, "input_bytes": 32, "rng_seed": 1234,
              "execution_backend": "in-memory OK, no edges or comparisons", "checksum": next(iter(checksums)),
              "samples": samples, "medians": medians, "candidate_source_sha256": hashes}
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(medians))


if __name__ == "__main__":
    main()
