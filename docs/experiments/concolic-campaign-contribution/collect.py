#!/usr/bin/env python3
# Сбор сырья эксперимента concolic-campaign-contribution (task-156, ADR-0036).
#
# Две клетки одного и того же бинарника, различающиеся ОДНИМ флагом:
#   armed — концолическая рука взведена (умолчание);
#   off   — та же сборка с --no-concolic (task-153).
# Детерминированная стадия выключена в ОБЕИХ клетках (--max-det-steps 0),
# бюджет задан числом исполненных входов и одинаков в обеих клетках.
#
# Цель инструментируется ДВУМЯ проходами: BranchTracePass (канал значений
# ветвлений, ADR-0033) и EdgeCoveragePass. Без первого рука структурно слепа
# (нет записей ветвлений -> нет привязок), и сравнение было бы бессодержательным.
#
# Пути в выводе печатаются относительно корня репозитория; скрэтч-каталог
# маскируется как <work>, корень — как <repo>.
import argparse
import hashlib
import json
import os
import random
import re
import subprocess
import sys
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "scripts", "stats"))
from mannwhitney import mannwhitneyu, holm_bonferroni  # noqa: E402
from a12 import a12  # noqa: E402

GEN = "docs/experiments/cmp-baselines-preflight/gen_target.py"
BRANCH_SO = "build/src/instrumentation/branch_trace_pass/libBranchTracePass.so"
EDGE_SO = "build/src/instrumentation/edge_coverage_pass/libEdgeCoveragePass.so"
COV_SO = "build/src/runtime/coverage/libmlfuzzz3_cov.so"
COV_DIR = "build/src/runtime/coverage"
FUZZER = "build/src/cli/fuzzer"
EXEC_SERVER = "build/exec-server-bin"
# Предусловие потолка снято на том же профиле цели (тот же генератор, те же
# --seed/--funcs/--cmps) в mutator-unsaturated-ceiling; здесь оно только
# цитируется, заново не измеряется.
CAL = "docs/experiments/mutator-unsaturated-ceiling/raw/raw-calibration-p2-multibyte-wide.txt"


def mask(s, work):
    return s.replace(work, "<work>").replace(ROOT, "<repo>")


def md5f(path):
    with open(path, "rb") as fh:
        return hashlib.md5(fh.read()).hexdigest()


def make_corpus(outdir, count, seed, min_len, max_len):
    # Тот же алгоритм и та же последовательность ГПСЧ, что в
    # docs/experiments/mutator-unsaturated-ceiling/collect.py:196 — сиды
    # побайтово совпадают с прежними кампаниями на этом профиле.
    os.makedirs(outdir, exist_ok=True)
    rnd = random.Random(seed)
    names = []
    for i in range(count):
        n = rnd.randrange(min_len, max_len + 1)
        data = bytes(rnd.randrange(256) for _ in range(n))
        name = "c%02d.bin" % i
        with open(os.path.join(outdir, name), "wb") as fh:
            fh.write(data)
        print("CCC seed_corpus file=%s bytes=%d md5=%s" % (name, n, hashlib.md5(data).hexdigest()))
        names.append(os.path.join(outdir, name))
    print("CCC seed_corpus_meta files=%d rng_seed=%d minlen=%d maxlen=%d"
          % (count, seed, min_len, max_len))
    return names


def run_cell(work, target, seeds_dir, arm, r, execs, timeout):
    out_dir = os.path.join(work, "%s-r%d" % (arm, r))
    cmd = [os.path.join(ROOT, FUZZER),
           "--exec-server", os.path.join(ROOT, EXEC_SERVER),
           "--target", target,
           "--cov-library", os.path.join(ROOT, COV_SO),
           "--seed-dir", seeds_dir,
           "--out-dir", out_dir,
           "--mutator", "havoc",
           "--max-det-steps", "0",
           "--max-iterations", str(execs),
           "--metrics-interval", str(execs),
           "--seed", str(r)]
    if arm == "off":
        cmd.append("--no-concolic")
    print("CCC cmd arm=%s r=%d %s" % (arm, r, mask(" ".join(cmd), work)))
    t0 = time.time()
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    wall = time.time() - t0
    rec = None
    mpath = os.path.join(out_dir, "metrics.jsonl")
    if os.path.exists(mpath):
        with open(mpath) as fh:
            lines = [ln for ln in fh.read().splitlines() if ln.strip()]
        if lines:
            rec = json.loads(lines[-1])
    if rec is None:
        m = re.search(r"\{.*\}", p.stdout or "")
        rec = json.loads(m.group(0)) if m else {}
    print("CCC run arm=%s r=%d rc=%d wall=%.2f %s" % (arm, r, p.returncode, wall, json.dumps(rec, sort_keys=True)))
    if p.returncode != 0:
        print("CCC run_stderr arm=%s r=%d %s" % (arm, r, mask((p.stderr or "").strip()[:400], work)))
    return rec


def read_raw(path):
    """Разбор уже снятого сырья: строки `CCC run arm=<arm> r=<r> {json}`."""
    armed, off = {}, {}
    sites = []
    for ln in open(path):
        m = re.match(r"CCC run arm=(\w+) r=(\d+) rc=\d+ wall=[\d.]+ (\{.*\})\s*$", ln.strip())
        if m:
            (armed if m.group(1) == "armed" else off)[int(m.group(2))] = json.loads(m.group(3))
        m = re.match(r"CCC channel_grep site=(.*)$", ln.strip())
        if m:
            sites.append(m.group(1))
    # Счёт потребителей: строки grep вне транспорта минус комментарии. Грепу
    # одинаково видны вызов и упоминание в комментарии, а потребитель — только
    # тот, кто РЕАЛЬНО читает записи; поэтому печатаются оба числа.
    outside = [x for x in sites if not x.startswith("src/core/runner.")]
    code = [x for x in outside
            if not re.sub(r"^[^:]+:\d+:\s*", "", x).startswith(("//", "*", "/*"))]
    print("CCC channel_consumer_count grep_lines_outside_transport=%d of_them_comments=%d "
          "real_call_sites=%d sites=%s"
          % (len(outside), len(outside) - len(code), len(code),
             ",".join(re.match(r"^([^:]+:\d+)", x).group(1) for x in code) or "-"))
    return ([armed[k] for k in sorted(armed)], [off[k] for k in sorted(off)], len(code))


def fmt_list(xs, f="%d"):
    return ";".join(f % x for x in xs)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--work", required=True)
    ap.add_argument("--n", type=int, default=10)
    ap.add_argument("--execs", type=int, default=10000)
    ap.add_argument("--timeout", type=float, default=900.0)
    ap.add_argument("--headline", default="")
    ap.add_argument("--phase", choices=["collect", "analyze"], default="collect")
    ap.add_argument("--raw", default="")
    args = ap.parse_args()

    work = os.path.abspath(args.work)
    os.makedirs(work, exist_ok=True)
    os.chdir(ROOT)

    if args.phase == "analyze":
        armed, off, n_consumers = read_raw(args.raw)
        print("CCC analyze src=%s runs_parsed=%d channel_consumers=%d"
              % (args.raw, len(armed) + len(off), n_consumers))
        report(armed, off, n_consumers, args)
        return

    print("CCC meta experiment=concolic-campaign-contribution task=task-156 adr=0036")
    print("CCC meta n_per_arm=%d execs_budget=%d arms=armed,off det_stage=off(--max-det-steps 0)"
          % (args.n, args.execs))
    print("CCC meta clang=%s" % subprocess.run(["clang", "--version"], capture_output=True,
                                               text=True).stdout.splitlines()[0])

    # --- цель ---
    tgt_c = os.path.join(work, "target.c")
    gen_cmd = ["python3", GEN, "--seed", "20260910", "--funcs", "200", "--cmps", "60", "-o", tgt_c]
    print("CCC cmd_target %s" % mask(" ".join(gen_cmd), work))
    out = subprocess.run(gen_cmd, capture_output=True, text=True, check=True)
    for ln in out.stdout.splitlines():
        print("CCC gen_target %s" % mask(ln, work))
    target = os.path.join(work, "target")
    build_cmd = ["clang", "-O2", "-fpass-plugin=" + os.path.join(ROOT, BRANCH_SO),
                 "-fpass-plugin=" + os.path.join(ROOT, EDGE_SO),
                 "-o", target, tgt_c, os.path.join(ROOT, COV_SO),
                 "-Wl,-rpath," + os.path.join(ROOT, COV_DIR)]
    print("CCC cmd_target_build %s" % mask(" ".join(build_cmd), work))
    subprocess.run(build_cmd, check=True)
    print("CCC target md5=%s bytes=%d" % (md5f(target), os.path.getsize(target)))

    # --- сиды ---
    seeds_dir = os.path.join(work, "seeds")
    make_corpus(seeds_dir, 3, 20260910, 128, 512)

    # --- потребители канала значений ветвлений (пункт 6 наряда) ---
    # Потребитель канала — тот, кто ЧИТАЕТ записи ветвлений на рабочем пути.
    # Транспорт (src/core/runner.*) их только достаёт, поэтому объявление и
    # определение LastBranchRecords исключены из счёта потребителей.
    grep = subprocess.run(["grep", "-rn", "LastBranchRecords()", "src"],
                          capture_output=True, text=True)
    consumers = [ln for ln in grep.stdout.splitlines()
                 if ln and not ln.startswith("src/core/runner.")]
    for ln in grep.stdout.splitlines():
        print("CCC channel_grep site=%s" % ln.strip())
    print("CCC channel_consumers n=%d (вне транспорта src/core/runner.*)" % len(consumers))

    # --- клетки ---
    armed, off = [], []
    for r in range(1, args.n + 1):
        armed.append(run_cell(work, target, seeds_dir, "armed", r, args.execs, args.timeout))
        off.append(run_cell(work, target, seeds_dir, "off", r, args.execs, args.timeout))
    if args.phase == "collect":
        print("CCC collect_done runs=%d (разбор — второй фазой по этому же сырью)" % (2 * args.n))
        return
    report(armed, off, len(consumers), args)


def report(armed, off, n_consumers, args):

    def col(recs, key):
        return [int(x.get(key, -1)) for x in recs]

    ca, co = col(armed, "edges"), col(off, "edges")
    ea, eo = col(armed, "execs"), col(off, "execs")
    ka, ko = col(armed, "concolic_calls"), col(off, "concolic_calls")
    ha, ho = col(armed, "havoc_execs"), col(off, "havoc_execs")

    print("CCC series arm=armed cells=%s" % fmt_list(ca))
    print("CCC series arm=off cells=%s" % fmt_list(co))
    print("CCC series arm=armed execs=%s" % fmt_list(ea))
    print("CCC series arm=off execs=%s" % fmt_list(eo))
    print("CCC series arm=armed concolic_calls=%s" % fmt_list(ka))
    print("CCC series arm=off concolic_calls=%s" % fmt_list(ko))
    print("CCC series arm=armed havoc_execs=%s" % fmt_list(ha))
    print("CCC series arm=off havoc_execs=%s" % fmt_list(ho))

    # равенство бюджета — счётом из сырья по каждому повтору, не объявлением
    all_equal = all(a == b == args.execs for a, b in zip(ea, eo))
    print("CCC budget_equality per_repeat=%s all_equal=%s target_budget=%d"
          % (";".join("r%d:%d=%d:%s" % (i + 1, a, b, "eq" if a == b else "ne")
                      for i, (a, b) in enumerate(zip(ea, eo))),
             "yes" if all_equal else "no", args.execs))
    hav_diff = [a - b for a, b in zip(ha, ho)]
    print("CCC havoc_divergence armed_minus_off=%s median=%.1f"
          % (fmt_list(hav_diff, "%+d"), sorted(hav_diff)[len(hav_diff) // 2]))

    # рука действительно срабатывала?
    armed_fired = all(x > 0 for x in ka)
    off_silent = all(x == 0 for x in ko)
    print("CCC arm_fired armed_all_positive=%s off_all_zero=%s armed_min=%d armed_max=%d"
          % ("yes" if armed_fired else "no", "yes" if off_silent else "no",
             min(ka) if ka else -1, max(ka) if ka else -1))
    # чем съеден бюджет, если рука не сработала
    for name, recs in (("armed", armed), ("off", off)):
        for k in ("concolic_no_candidate", "concolic_no_binding", "concolic_unsat",
                  "concolic_timeout", "concolic_error", "concolic_budget_skips",
                  "concolic_candidates", "concolic_edges", "concolic_crashes"):
            print("CCC detail arm=%s %s=%s" % (name, k, fmt_list(col(recs, k))))

    # --- статистика ---
    u, p_raw = mannwhitneyu(ca, co)
    p_holm = float(holm_bonferroni([p_raw])[0])
    e = a12(ca, co)
    med_a = sorted(ca)[len(ca) // 2]
    med_o = sorted(co)[len(co) // 2]
    print("CCC stat pair=armed_vs_off u=%s p_raw=%.9g p_holm=%.9g alpha=0.05 significant=%s "
          "a12=%.3f n_x=%d n_y=%d (разборщики scripts/stats/mannwhitney.py и scripts/stats/a12.py)"
          % (u, p_raw, p_holm, "yes" if p_holm < 0.05 else "no", e, len(ca), len(co)))
    print("CCC medians cells_armed=%d cells_off=%d delta_cells=%+.1f" % (med_a, med_o, med_a - med_o))

    # --- контроль потолка по всем 20 клеткам ---
    ceiling = edges_total = None
    with open(CAL) as fh:
        for ln in fh:
            m = re.search(r"ceiling_reached source=union_random_and_arm cells=(\d+)", ln)
            if m:
                ceiling = int(m.group(1))
            m = re.search(r"MUC probes cov_map_ir=\d+ edges_total=(\d+)", ln)
            if m:
                edges_total = int(m.group(1))
    print("CCC precondition src=%s ceiling_reached=%s edges_total=%s" % (CAL, ceiling, edges_total))
    hr_a = [1.0 - v / ceiling for v in ca]
    hr_o = [1.0 - v / ceiling for v in co]
    hmin = min(hr_a + hr_o)
    saturated = hmin <= 0.0
    print("CCC headroom cells=20 headroom_armed=%s headroom_off=%s min=%.4f saturated=%s"
          % (fmt_list(hr_a, "%.4f"), fmt_list(hr_o, "%.4f"), hmin, "yes" if saturated else "no"))

    if not armed_fired:
        wins = "undecidable"
    elif p_holm < 0.05 and med_a > med_o:
        wins = "yes"
    else:
        wins = "no"
    print("VERDICT: CONCOLIC-CAMPAIGN-CONTRIBUTION: target=p2-multibyte-wide-gen_target-seed20260910, "
          "n_per_arm=%d, budget_equalized_on=executed_inputs, all_equal=%s, "
          "concolic_calls_armed=%s, concolic_calls_off=%s, cells_armed=%d, cells_off=%d, "
          "delta_cells=%+.1f, headroom_frac=%s, saturated=%s, p_holm=%.6g, a12=%.3f, "
          "channel_consumers=%d, arm_wins=%s, new_runs=%d, src_modified=0, headline=\"%s\""
          % (args.n, "yes" if all_equal else "no", fmt_list(ka), fmt_list(ko), med_a, med_o,
             med_a - med_o, fmt_list(hr_a + hr_o, "%.4f"), "yes" if saturated else "no",
             p_holm, e, n_consumers, wins, 2 * args.n, args.headline))


if __name__ == "__main__":
    main()
