#!/usr/bin/env bash
# Сырьё эксперимента «статическая цена собственной инструментации» (task-126,
# ADR-0024 / ADR-0033).
#
# Ни одного прогона фаззера, ни одной кампании, ни обращения к сети: цель
# порождается генератором с фиксированным зерном и собирается шестью плечами,
# у каждого замеряется время сборки, размер бинаря, размер секции кода и число
# вставленных проб.
#
# Скрипт запускается из ЛЮБОГО каталога — корень репозитория вычисляется от
# расположения самого скрипта, поэтому вывод не зависит от cwd. Рабочие файлы
# сборки кладутся во временный каталог вне репозитория и в выводе заменяются
# на <work>, чтобы в сырьё не попадали абсолютные пути. Каталог остаётся на
# диске после прогона намеренно: скрипт ничего не удаляет.
#
# ПРЕДУСЛОВИЕ: плагины инструментации и рантайм карты собраны в build/ —
#   cmake --build build --target EdgeCoveragePass BranchTracePass mlfuzzz3_cov
#
# Использование (перенаправлены И stdout, И stderr):
#   bash docs/experiments/instrumentation-cost/run.sh --repeats 5 \
#     > docs/experiments/instrumentation-cost/raw-instrumentation-cost.txt 2>&1
# Exit: 0 — все шесть плеч обработаны (плечо могло УПАСТЬ и это не ошибка
# скрипта: падение публикуется строкой arm=... status=failed с причиной).
set -uo pipefail

REPEATS=5
SEED=20260908
FUNCS=120
BRANCHES=60
while [ $# -gt 0 ]; do
  case "$1" in
    --repeats) REPEATS="$2"; shift 2 ;;
    --seed) SEED="$2"; shift 2 ;;
    --funcs) FUNCS="$2"; shift 2 ;;
    --branches) BRANCHES="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/mlfuzzz3-instrcost.XXXXXX")"

EDGE_SO="build/src/instrumentation/edge_coverage_pass/libEdgeCoveragePass.so"
BRANCH_SO="build/src/instrumentation/branch_trace_pass/libBranchTracePass.so"
COV_SO="build/src/runtime/coverage/libmlfuzzz3_cov.so"
COV_DIR="build/src/runtime/coverage"

echo "# task-126 — статическая цена собственной инструментации (ADR-0024, ADR-0033)"
echo "# commit: $(git -C "$ROOT" rev-parse --short HEAD)"
echo "# repeats=$REPEATS seed=$SEED funcs=$FUNCS branches_per_func=$BRANCHES"
echo "# Перегенерация из корня репозитория (перенаправлены И stdout, И stderr):"
echo "#   bash docs/experiments/instrumentation-cost/run.sh --repeats $REPEATS \\"
echo "#     --seed $SEED --funcs $FUNCS --branches $BRANCHES \\"
echo "#     > docs/experiments/instrumentation-cost/raw-instrumentation-cost-n$REPEATS.txt 2>&1"
echo "# Новых прогонов фаззинга: 0. Новых кампаний: 0. Правок src/: 0."
echo "#"
echo "# ПРАВИЛА, ВЫПИСАННЫЕ ДО ЗАМЕРА:"
echo "#  R1 отбрасывание прогрева: НЕ применяется. Публикуются ВСЕ значения,"
echo "#     медиана считается по всем без исключения, первый повтор не отбрасывается."
echo "#  R2 время сборки: wall-clock полной команды компиляции+линковки, каждый"
echo "#     повтор в свежий выходной файл, секунды с тремя знаками."
echo "#  R3 счёт проб, отдельно для каждой схемы (единицы РАЗНЫЕ, см. R4)."
echo "#     ВАЖНО: считается число ВСТАВЛЕННЫХ проб, а не выживших после -O2."
echo "#     Счёт по релокациям в -O2-объектнике НЕПРИГОДЕН и не применяется: при"
echo "#     -O2 все статические функции цели инлайнятся в одну, адрес карты"
echo "#     материализуется один раз на функцию, и счётчик даёт 2 вместо тысяч."
echo "#     Поэтому наши плечи считаются по LLVM IR, порождённому ТЕМ ЖЕ пассом"
echo "#     на -O0 (пасс регистрируется на PipelineStartEP, то есть вставка та же):"
echo "#     plain       — проб нет по построению; все счётчики печатаются, все нули;"
echo "#     ours        — число вхождений '@__mlfuzzz3_cov_map' в -O0 IR (одно на"
echo "#                   вставленную рёберную пробу — доступ к карте);"
echo "#     ours_branch — то же плюс число вызовов '@fuzzer_rt_log_branch_cmp'"
echo "#                   в -O0 IR (один на пробу канала); печатаются оба числа;"
echo "#     pcguard     — число guard-слов: СУММА размеров всех секций"
echo "#                   '__sancov_guards' в -O2 .o, делённая на 4 (секций две:"
echo "#                   основная и хвостовая, суммируются обе); рядом печатается"
echo "#                   число, которое сам afl-clang-fast сообщает в stderr;"
echo "#     classic     — число из stderr afl-clang-fast ('Instrumented N');"
echo "#     sancov      — сумма '__sancov_guards' / 4 по тому же правилу."
echo "#  R4 несопоставимость: 'ours' считает РЁБРА (пара блоков), 'pcguard' и"
echo "#     'sancov' считают ГВАРДЫ (точки вставки на блок), 'classic' считает"
echo "#     точки вставки AFL. Пары (ours,pcguard), (ours,sancov), (ours,classic)"
echo "#     НЕСОПОСТАВИМЫ по абсолютному числу проб и помечаются как таковые."
echo "#     Сопоставимы между собой только 'ours' и 'ours_branch'."
echo "#  R5 цена канала значений ветвлений: ТОЛЬКО прямая разность наших двух"
echo "#     плеч (ours_branch минус ours), без участия чужих плеч."
echo "#  R6 плечо, которое не собралось, печатается строкой status=failed с"
echo "#     текстом ошибки и НЕ выбрасывается; arms_built + arms_failed = 6."
echo "#  R7 поправка Д3 (выписана до замера): grep по -O0 IR ловит ещё и строку"
echo "#     ОБЪЯВЛЕНИЯ глобала карты, поэтому публикуемое число проб равно"
echo "#     probes_cov_map_ir минус 1. Печатаются ОБА числа: сырое и поправленное."
echo "#     Для чужих плеч поправка неприменима и печатается '-'."
echo "#  R8 поправка Д1 (classic): число проб снимается ОТДЕЛЬНОЙ диагностической"
echo "#     сборкой с AFL_DEBUG=1 ВНЕ цикла замера времени — тайминги от этого не"
echo "#     зависят. Если и она молчит, печатается '-' и число не публикуется."
echo "#  R9 поправка Д2 (sancov/pcguard): рядом с числом гвардов из -O2 объектника"
echo "#     печатается число из -O0 объектника той же командой. Расхождение -O0 и"
echo "#     -O2 РАЗДЕЛЯЕТ две гипотезы Д2: если на -O0 гвардов тысячи, схема"
echo "#     инструментирует то, что осталось ПОСЛЕ оптимизаций, и правило счёта"
echo "#     верно; если и на -O0 их единицы, дефект в конфигурации плеча."
echo "#"
echo "# СРЕДА:"
echo "#   clang:          $(clang --version | head -1)"
echo "#   afl-clang-fast: $(afl-clang-fast --version 2>&1 | head -1)"
echo "#   uname:          $(uname -sr)"
echo ""

echo "== GEN =="
python3 "$HERE/gen_target.py" --seed "$SEED" --funcs "$FUNCS" --branches "$BRANCHES" -o "$WORK/target.c"
python3 "$HERE/gen_target.py" --seed "$SEED" --funcs "$FUNCS" --branches "$BRANCHES" -o "$WORK/target_again.c"
if cmp -s "$WORK/target.c" "$WORK/target_again.c"; then
  echo "gen_determinism=OK (повторный запуск дал побайтово тот же файл)"
else
  echo "gen_determinism=FAIL"
fi
echo "target_md5=$(md5sum < "$WORK/target.c" | cut -d' ' -f1) target_bytes=$(stat -c%s "$WORK/target.c") target_lines=$(wc -l < "$WORK/target.c")"
clang -O0 -S -emit-llvm -o "$WORK/target_O0.ll" "$WORK/target.c" 2>/dev/null
BB_LABELS=$(grep -cE '^[0-9]+:|^[A-Za-z._][A-Za-z0-9._]*:' "$WORK/target_O0.ll")
BB_DEFINES=$(grep -c '^define ' "$WORK/target_O0.ll")
BB=$((BB_LABELS + BB_DEFINES))
echo "bb_count_llvm_ir_O0=$BB (метки блоков $BB_LABELS + входные блоки функций $BB_DEFINES; -O0 IR, до оптимизаций)"
BB_O2=$(clang -O2 -S -emit-llvm -o - "$WORK/target.c" 2>/dev/null | grep -cE '^[0-9]+:|^[A-Za-z._][A-Za-z0-9._]*:')
echo "bb_count_llvm_ir_O2_labels=$BB_O2 (для сведения: после -O2 цель инлайнится в одну функцию)"
echo ""

ARM_KEYS=(plain ours ours_branch pcguard classic sancov)

cmd_for() {
  case "$1" in
    plain)       echo "clang -O2 -o <work>/out_plain <work>/target.c" ;;
    ours)        echo "clang -O2 -fpass-plugin=$EDGE_SO -o <work>/out_ours <work>/target.c $COV_SO -Wl,-rpath,$COV_DIR" ;;
    ours_branch) echo "clang -O2 -fpass-plugin=$BRANCH_SO -fpass-plugin=$EDGE_SO -o <work>/out_ours_branch <work>/target.c $COV_SO -Wl,-rpath,$COV_DIR" ;;
    pcguard)     echo "afl-clang-fast -O2 -o <work>/out_pcguard <work>/target.c" ;;
    classic)     echo "AFL_LLVM_INSTRUMENT=CLASSIC afl-clang-fast -O2 -o <work>/out_classic <work>/target.c" ;;
    sancov)      echo "clang -O2 -fsanitize-coverage=trace-pc-guard -o <work>/out_sancov <work>/target.c $COV_SO -Wl,-rpath,$COV_DIR" ;;
  esac
}

build_once() {
  local arm="$1" out="$2" errlog="$3"
  case "$arm" in
    plain)
      clang -O2 -o "$out" "$WORK/target.c" 2>"$errlog" ;;
    ours)
      clang -O2 -fpass-plugin="$ROOT/$EDGE_SO" -o "$out" "$WORK/target.c" \
        "$ROOT/$COV_SO" -Wl,-rpath,"$ROOT/$COV_DIR" 2>"$errlog" ;;
    ours_branch)
      clang -O2 -fpass-plugin="$ROOT/$BRANCH_SO" -fpass-plugin="$ROOT/$EDGE_SO" -o "$out" "$WORK/target.c" \
        "$ROOT/$COV_SO" -Wl,-rpath,"$ROOT/$COV_DIR" 2>"$errlog" ;;
    pcguard)
      afl-clang-fast -O2 -o "$out" "$WORK/target.c" 2>"$errlog" ;;
    classic)
      AFL_LLVM_INSTRUMENT=CLASSIC afl-clang-fast -O2 -o "$out" "$WORK/target.c" 2>"$errlog" ;;
    sancov)
      clang -O2 -fsanitize-coverage=trace-pc-guard -o "$out" "$WORK/target.c" \
        "$ROOT/$COV_SO" -Wl,-rpath,"$ROOT/$COV_DIR" 2>"$errlog" ;;
  esac
}

build_obj() {
  local arm="$1" out="$2"
  case "$arm" in
    plain)       clang -O2 -c -o "$out" "$WORK/target.c" 2>/dev/null ;;
    ours)        clang -O2 -fpass-plugin="$ROOT/$EDGE_SO" -c -o "$out" "$WORK/target.c" 2>/dev/null ;;
    ours_branch) clang -O2 -fpass-plugin="$ROOT/$BRANCH_SO" -fpass-plugin="$ROOT/$EDGE_SO" -c -o "$out" "$WORK/target.c" 2>/dev/null ;;
    pcguard)     afl-clang-fast -O2 -c -o "$out" "$WORK/target.c" 2>/dev/null ;;
    classic)     AFL_LLVM_INSTRUMENT=CLASSIC afl-clang-fast -O2 -c -o "$out" "$WORK/target.c" 2>/dev/null ;;
    sancov)      clang -O2 -fsanitize-coverage=trace-pc-guard -c -o "$out" "$WORK/target.c" 2>/dev/null ;;
  esac
}

build_ir() {   # LLVM IR на -O0 с теми же пассами: счёт ВСТАВЛЕННЫХ проб (см. R3)
  local arm="$1" out="$2"
  case "$arm" in
    plain)       clang -O0 -S -emit-llvm -o "$out" "$WORK/target.c" 2>/dev/null ;;
    ours)        clang -O0 -S -emit-llvm -fpass-plugin="$ROOT/$EDGE_SO" -o "$out" "$WORK/target.c" 2>/dev/null ;;
    ours_branch) clang -O0 -S -emit-llvm -fpass-plugin="$ROOT/$BRANCH_SO" -fpass-plugin="$ROOT/$EDGE_SO" -o "$out" "$WORK/target.c" 2>/dev/null ;;
    *)           clang -O0 -S -emit-llvm -o "$out" "$WORK/target.c" 2>/dev/null ;;
  esac
}

build_obj_O0() {  # R9: тот же объектник, но без оптимизаций — разделяет гипотезы Д2
  local arm="$1" out="$2"
  case "$arm" in
    pcguard)     afl-clang-fast -O0 -c -o "$out" "$WORK/target.c" 2>/dev/null ;;
    classic)     AFL_LLVM_INSTRUMENT=CLASSIC afl-clang-fast -O0 -c -o "$out" "$WORK/target.c" 2>/dev/null ;;
    sancov)      clang -O0 -fsanitize-coverage=trace-pc-guard -c -o "$out" "$WORK/target.c" 2>/dev/null ;;
    *)           return 1 ;;
  esac
}

guards_of() {  # сумма ВСЕХ секций __sancov_guards в объектнике, делённая на 4
  size -A "$1" 2>/dev/null | awk '$1=="__sancov_guards"{s+=$2} END{print s+0}'
}

afl_debug_count() {  # R8: AFL_DEBUG=1, отдельная сборка, тайминги не затрагивает
  local arm="$1" log="$2"
  case "$arm" in
    pcguard) AFL_DEBUG=1 afl-clang-fast -O2 -c -o "$WORK/dbg_$arm.o" "$WORK/target.c" 2>"$log" ;;
    classic) AFL_DEBUG=1 AFL_LLVM_INSTRUMENT=CLASSIC afl-clang-fast -O2 -c -o "$WORK/dbg_$arm.o" "$WORK/target.c" 2>"$log" ;;
    *) return 1 ;;
  esac
}

for arm in "${ARM_KEYS[@]}"; do
  echo "== ARM $arm =="
  echo "cmd: $(cmd_for "$arm")"
  out="$WORK/out_$arm"
  errlog="$WORK/err_$arm"
  if ! build_once "$arm" "$out" "$errlog"; then
    echo "arm=$arm status=failed reason=<<$(head -c 400 "$errlog" | tr '\n' ' ')>>"
    echo ""
    continue
  fi
  times=()
  for r in $(seq 1 "$REPEATS"); do
    s=$(date +%s.%N)
    build_once "$arm" "$out" "$errlog"
    rc=$?
    e=$(date +%s.%N)
    d=$(awk -v a="$s" -v b="$e" 'BEGIN{printf "%.3f", b-a}')
    times+=("$d")
    echo "arm=$arm repeat=$r build_s=$d rc=$rc"
  done
  med=$(printf '%s\n' "${times[@]}" | sort -n | awk '{v[NR]=$1} END{ if (NR%2) printf "%.3f", v[(NR+1)/2]; else printf "%.3f", (v[NR/2]+v[NR/2+1])/2 }')
  mn=$(printf '%s\n' "${times[@]}" | sort -n | head -1)
  mx=$(printf '%s\n' "${times[@]}" | sort -n | tail -1)
  bin_bytes=$(stat -c%s "$out")
  text_bytes=$(size -A "$out" | awk '$1==".text"{print $2}')
  obj="$WORK/obj_$arm.o"
  build_obj "$arm" "$obj"
  irfile="$WORK/ir_$arm.ll"
  build_ir "$arm" "$irfile"
  probes_map=$(grep -c '@__mlfuzzz3_cov_map' "$irfile" 2>/dev/null)
  probes_branch=$(grep -c 'call void @fuzzer_rt_log_branch_cmp' "$irfile" 2>/dev/null)
  guards_bytes=$(guards_of "$obj")
  guards=$((guards_bytes / 4))
  afl_reported=$(grep -oE 'Instrumented [0-9]+' "$errlog" 2>/dev/null | grep -oE '[0-9]+' | head -1)
  [ -z "$afl_reported" ] && afl_reported="-"
  # R7: поправка на строку объявления глобала карты
  case "$arm" in
    ours|ours_branch) probes_map_corr=$((probes_map - 1)) ;;
    plain)            probes_map_corr=0 ;;
    *)                probes_map_corr="-" ;;
  esac
  # R8: число проб classic/pcguard из AFL_DEBUG=1 (отдельная сборка вне замера)
  afl_dbg="-"
  if afl_debug_count "$arm" "$WORK/errdbg_$arm"; then
    afl_dbg=$(grep -oE 'Instrumented [0-9]+' "$WORK/errdbg_$arm" 2>/dev/null | grep -oE '[0-9]+' | head -1)
    [ -z "$afl_dbg" ] && afl_dbg="-"
  fi
  # R9: гварды в -O0 объектнике той же схемы
  guards_O0="-"
  if build_obj_O0 "$arm" "$WORK/obj_O0_$arm.o"; then
    g0=$(guards_of "$WORK/obj_O0_$arm.o")
    guards_O0=$((g0 / 4))
  fi
  echo "arm=$arm n=$REPEATS build_s_median=$med build_s_min=$mn build_s_max=$mx bin_bytes=$bin_bytes text_bytes=$text_bytes probes_cov_map_ir=$probes_map probes_cov_map_corrected=$probes_map_corr probes_branch_ir=$probes_branch sancov_guards=$guards sancov_guards_O0=$guards_O0 guards_section_bytes=$guards_bytes afl_reported=$afl_reported afl_debug_reported=$afl_dbg"
  echo ""
done

echo "== END =="
