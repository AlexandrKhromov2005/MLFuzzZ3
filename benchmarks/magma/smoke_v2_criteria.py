#!/usr/bin/env python3
"""Критерии smoke кампании v2 (ADR 0048), проверяемые по её артефактам.

Читает результат прогона `smoke_comparative_run_tiff.sh --v2` и ничего не
запускает сам. Пять критериев зарегистрированы в шапке того скрипта ДО
прогона; здесь они только считаются. Порог не берётся ни из одного места,
кроме констант ниже, и после прогона не двигается.

Переменные окружения: V2_WORK, V2_OUT, V2_BUDGET (их ставит smoke-скрипт).
Код возврата: 0 — smoke=PASS, 1 — smoke=FAIL.
"""
from __future__ import annotations

import json
import os
import sys

ARM_OURS = "mlfuzzz3"
ARM_NOCON = "mlfuzzz3-noconcolic"
ARMS = (ARM_OURS, ARM_NOCON, "afl-plain", "afl-cmplog", "libfuzzer")

ALIVE_FRACTION = 0.90   # К1: последняя отметка не раньше 90 % бюджета
TIME_SHARE_MAX = 0.30   # К2: доля времени солвера у плеча 1


def last_metrics(path):
    """Последняя ЦЕЛАЯ запись metrics.jsonl (последняя строка бывает обрвана)."""
    try:
        lines = open(path, encoding="utf-8", errors="replace").readlines()
    except OSError:
        return None
    for line in reversed(lines):
        line = line.strip()
        if not line:
            continue
        try:
            return json.loads(line)
        except ValueError:
            continue
    return None


def main() -> int:
    work = os.environ.get("V2_WORK", "")
    budget = float(os.environ.get("V2_BUDGET", "600"))
    trial_dir = os.path.join(work, "trials", "trial_000")
    ckpt = os.path.join(work, "checkpoints", "trial_000.json")
    art_root = os.path.join(trial_dir, "artifacts")

    results, notes = {}, []

    data = None
    if os.path.exists(ckpt):
        try:
            data = json.load(open(ckpt, encoding="utf-8"))
        except ValueError as exc:
            notes.append(f"чекпойнт не разобран: {exc}")
    else:
        notes.append("чекпойнт trial_000.json отсутствует")

    fuzzers = (data or {}).get("fuzzers", {})

    # --- К1: все плечи дожили до конца бюджета ---
    alive, alive_detail = 0, []
    for arm in ARMS:
        series = fuzzers.get(arm, {}).get("execs") or []
        last_t = max((t for t, _n in series), default=0.0)
        ok = last_t >= ALIVE_FRACTION * budget
        alive += 1 if ok else 0
        alive_detail.append(f"{arm}={last_t:.0f}s{'' if ok else ' (РАНО)'}")
    results["К1"] = (alive == len(ARMS),
                     f"дожили {alive}/{len(ARMS)}: " + ", ".join(alive_detail))

    # --- К4: счётчик исполнений в каждом снапшоте у каждого плеча ---
    execs_ok, execs_detail = 0, []
    for arm in ARMS:
        series = fuzzers.get(arm, {}).get("execs") or []
        missing = sum(1 for _t, n in series if n is None)
        ok = bool(series) and missing == 0
        execs_ok += 1 if ok else 0
        execs_detail.append(f"{arm}={len(series)}снап/{missing}пусто")
    results["К4"] = (execs_ok == len(ARMS),
                     f"счётчик записан у {execs_ok}/{len(ARMS)}: " + ", ".join(execs_detail))

    # --- К2: плечо 1 — rate-limit жив и ограничивает ---
    m1 = last_metrics(os.path.join(art_root, ARM_OURS, "metrics.jsonl"))
    skips = m1.get("concolic_budget_skips") if m1 else None
    share = None
    if m1 and m1.get("elapsed"):
        share = m1.get("concolic_time_ms_total", 0) / (float(m1["elapsed"]) * 1000.0)
    results["К2"] = (skips is not None and skips > 0
                     and share is not None and share <= TIME_SHARE_MAX,
                     f"skips={skips}, доля времени солвера="
                     + ("н/д" if share is None else f"{share:.3f}"))

    # --- К3: плечо 2 — солвер разоружён ---
    m2 = last_metrics(os.path.join(art_root, ARM_NOCON, "metrics.jsonl"))
    calls = m2.get("concolic_calls") if m2 else None
    results["К3"] = (calls == 0, f"concolic_calls={calls}")

    # --- К5: артефакты трайла пережили его конец ---
    kept, kept_detail = 0, []
    for arm in ARMS:
        d = os.path.join(art_root, arm)
        n = 0
        for _root, _dirs, files in os.walk(d):
            n += len(files)
        if n > 0:
            kept += 1
        kept_detail.append(f"{arm}={n}")
    results["К5"] = (kept == len(ARMS),
                     f"каталогов с артефактами {kept}/{len(ARMS)}: " + ", ".join(kept_detail))

    print("=== КРИТЕРИИ SMOKE v2 (ADR 0048) ===")
    for key in ("К1", "К2", "К3", "К4", "К5"):
        ok, detail = results[key]
        print(f"{key}: {'PASS' if ok else 'FAIL'} — {detail}")
    for note in notes:
        print(f"ПРИМЕЧАНИЕ: {note}")

    passed = all(ok for ok, _ in results.values())
    share_txt = "н/д" if share is None else f"{share:.3f}"
    headline = (
        "оснастка кампании v2 готова: пятое плечо без солвера живёт, "
        "знаменатель пишется, артефакты трайла переживают его конец"
        if passed else
        "оснастка кампании v2 не готова: " +
        ", ".join(k for k in ("К1", "К2", "К3", "К4", "К5") if not results[k][0]) +
        " не взяты, кампания N=10 v2 не рекомендуется"
    )
    print(f"VERDICT: arms={len(ARMS)}, smoke_s={int(budget)}, "
          f"arm1_time_share={share_txt}, arm1_skips={skips}, "
          f"arm2_concolic_calls={calls}, execs_recorded={execs_ok}/{len(ARMS)}, "
          f"artifacts_kept={'yes' if kept == len(ARMS) else 'no'}, "
          f"smoke={'PASS' if passed else 'FAIL'}, campaign_launched=no, "
          f"headline=\"{headline}\"")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
