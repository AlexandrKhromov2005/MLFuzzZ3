#!/usr/bin/env python3
"""Разбор сырья эксперимента «статическая цена собственной инструментации» (task-126).

Читает файл сырья, печатает таблицу по плечам и поля строки VERDICT.
Ничего не запускает и ничего не изменяет: чистый разбор уже снятых чисел.

Запуск из корня репозитория (путь входа ОТНОСИТЕЛЬНЫЙ — иначе в вывод попадёт
абсолютный путь и сломает побайтовую воспроизводимость):
  python3 docs/experiments/instrumentation-cost/collect.py \
    docs/experiments/instrumentation-cost/raw-instrumentation-cost-n5.txt

Строки шапки сырья (начинающиеся с '#') при разборе отбрасываются: в них
процитированы имена полей, и без фильтра они попали бы в счёт как данные.
"""
import re
import sys

ARMS = ["plain", "ours", "ours_branch", "pcguard", "classic", "sancov"]


def parse(path):
    rows, failed = {}, {}
    bb = None
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if line.startswith("#"):          # шапка не данные, см. docstring
                continue
            line = line.rstrip("\n")
            m = re.match(r"^bb_count_llvm_ir_O0=(\d+)", line)
            if m:
                bb = int(m.group(1))
                continue
            m = re.match(r"^arm=(\w+) status=failed reason=<<(.*)>>$", line)
            if m:
                failed[m.group(1)] = m.group(2)
                continue
            if not line.startswith("arm=") or " n=" not in line:
                continue
            fields = dict(kv.split("=", 1) for kv in line.split() if "=" in kv)
            rows[fields["arm"]] = fields
    return bb, rows, failed


def num(rows, arm, key, cast=float):
    v = rows.get(arm, {}).get(key)
    if v is None or v == "-":
        return None
    return cast(v)


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: collect.py <raw-file>")
    path = sys.argv[1]
    bb, rows, failed = parse(path)
    print(f"вход: {path}")
    print(f"плеч с числами: {len(rows)}, плеч упавших: {len(failed)}, "
          f"базовых блоков в -O0 IR: {bb}")
    print()
    hdr = ("плечо", "сборка мед., с", "мин", "макс", "бинарь, Б", ".text, Б",
           "проб (см. R3/R4)")
    print(" | ".join(hdr))
    for arm in ARMS:
        if arm in failed:
            print(f"{arm} | ПЛЕЧО УПАЛО: {failed[arm]}")
            continue
        r = rows.get(arm)
        if r is None:
            print(f"{arm} | НЕТ СТРОКИ В СЫРЬЕ")
            continue
        if arm == "plain":
            probes = "0 (по построению)"
        elif arm == "ours":
            probes = f"{r['probes_cov_map_corrected']} рёберных"
        elif arm == "ours_branch":
            probes = (f"{r['probes_cov_map_corrected']} рёберных "
                      f"+ {r['probes_branch_ir']} канала")
        elif arm == "classic":
            probes = (f"AFL_DEBUG={r['afl_debug_reported']}, "
                      f"гвардов -O2={r['sancov_guards']}, -O0={r['sancov_guards_O0']}")
        else:
            probes = (f"гвардов -O2={r['sancov_guards']}, "
                      f"-O0={r['sancov_guards_O0']}")
        print(" | ".join([arm, r["build_s_median"], r["build_s_min"],
                          r["build_s_max"], r["bin_bytes"], r["text_bytes"],
                          probes]))
    print()

    plain_size = num(rows, "plain", "bin_bytes", int)
    ours_size = num(rows, "ours", "bin_bytes", int)
    ourb_size = num(rows, "ours_branch", "bin_bytes", int)
    pcg_size = num(rows, "pcguard", "bin_bytes", int)
    ours_t = num(rows, "ours", "build_s_median")
    ourb_t = num(rows, "ours_branch", "build_s_median")

    # R5: цена канала — ТОЛЬКО прямая разность наших двух плеч
    print("R5, прямая разность наших плеч (ours_branch минус ours):")
    print(f"  время сборки:  {ourb_t:.3f} - {ours_t:.3f} = {ourb_t - ours_t:+.3f} с "
          f"({(ourb_t / ours_t - 1) * 100:+.1f} %)")
    print(f"  размер бинаря: {ourb_size} - {ours_size} = {ourb_size - ours_size:+d} Б "
          f"({(ourb_size / ours_size - 1) * 100:+.1f} %)")
    nb = num(rows, "ours_branch", "probes_branch_ir", int)
    print(f"  проб канала:   {nb:+d}")
    print()

    def med(arm):
        v = num(rows, arm, "build_s_median")
        return "-" if v is None else f"{v:.2f}"

    pcg_t = num(rows, "pcguard", "build_s_median")
    # headline: одна фраза с результатом, требование формата отчёта эксперимента.
    # Числа берутся из тех же медиан, что и поля ниже; имён полей в фразе нет.
    if None in (ourb_t, ours_t, ourb_size, ours_size, pcg_t):
        headline = "неполное сырьё: собраны не все плечи, результат не сформулирован"
    else:
        cls_probes = rows.get("classic", {}).get("afl_debug_reported", "-")
        headline = (
            f"канал значений ветвлений стоит "
            f"{(ourb_t / ours_t - 1) * 100:+.0f} % времени сборки и "
            f"{(ourb_size / ours_size - 1) * 100:+.0f} % размера бинаря, "
            f"наша инструментация собирается в "
            f"{pcg_t / ourb_t:.1f} раза быстрее PCGUARD, "
            f"а плечо CLASSIC отказало — оно проинструментировало "
            f"{cls_probes} точки из {bb} блоков"
        )

    verdict = (
        "VERDICT: INSTRUMENTATION-COST: "
        f'headline="{headline}", '
        f"arms_built={len(rows)}, arms_failed={len(failed)}, bb_count={bb}, "
        f"build_s_plain={med('plain')}, build_s_ours={med('ours')}, "
        f"build_s_ours_branch={med('ours_branch')}, build_s_pcguard={med('pcguard')}, "
        f"build_s_classic={med('classic')}, build_s_sancov={med('sancov')}, "
        f"size_ratio_ours_over_plain={ours_size / plain_size:.2f}, "
        f"size_ratio_pcguard_over_plain={pcg_size / plain_size:.2f}, "
        f"branch_channel_build_overhead={ourb_t / ours_t:.2f}, "
        f"branch_channel_size_overhead={ourb_size / ours_size:.2f}, "
        "n_repeats=5, execs_measured=no, byte_repro_verified=no, "
        "classic_arm=degraded, new_fuzzing_runs=0, src_modified=0"
    )
    print(verdict)


if __name__ == "__main__":
    main()
