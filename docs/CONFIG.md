# Конфигурация

Реализованная YAML-секция `log` задаёт логирование для ядра и сервера.

| Поле | Значения | По умолчанию |
| --- | --- | --- |
| `log.level` | trace, debug, info, warn, error, critical | info |
| `log.format` | text, json | text |

В Go trace отображается в debug, а critical — в error. Отсутствующая секция
использует значения по умолчанию. Неизвестные ключи игнорируются.
Минимальный пример — [fuzzer.example.yaml](../config/fuzzer.example.yaml).

Параметры кампании передаются через CLI: `build/src/cli/fuzzer --help`.
Продуктовый LLM-бэкенд пока не реализован; его проектируемые параметры
не являются действующими настройками этого среза.

## Композиция кампании v1 (ADR-0056)

Рекомендуемый формат — независимая секция `composition:` в общей YAML:

```yaml
log:
  level: info
composition:
  schema_version: 1
  profile: hybrid-heuristic
  seed: 1234
  seed_scheduler: {type: round-robin}
  strategy_policy: {type: stagnation}
  stages:
    - {type: deterministic}
    - {type: mutation, mutator: havoc}
    - {type: i2s, binding: value_match, allow_incomplete: false}
    - {type: i2s_smt, binding: value_match, solver: z3, timeout_ms: 1000, allow_incomplete: false}
  admission: {type: coverage_novelty}
  campaign: {max_iterations: 10000, max_seconds: 0, max_det_steps: 0}
```

Полный пример — [composition.example.yaml](../config/composition.example.yaml).
Для отдельного файла композиции те же поля допускаются на верхнем уровне.
Общая секция log остаётся за пределами composition и сохраняет прежние
правила парсинга в C++/Go. Новая секция строго отклоняет неизвестные поля,
неизвестные модули, повторные стадии и несовместимые параметры. Версия 1
обязательна при наличии параметров композиции. Тихого fallback для явно
запрошенного отсутствующего модуля нет.

Приоритет: defaults выбранного профиля < явный YAML < явно переданный CLI.
Парсер запоминает присутствие флага, поэтому обычные CLI-defaults не затирают
YAML. `--profile` выбирает профиль; `--seed`, `--seed-scheduler`, `--mutator`,
лимиты и существующие солверные флаги переопределяют соответствующие поля.
`--no-concolic` явно удаляет i2s_smt из состава. Запуск:

```bash
fuzzer --config config/composition.example.yaml \
  --exec-server /path/to/exec-server --target /path/to/target \
  --cov-library /path/to/libmlfuzzz3_cov.so --out-dir /path/to/results \
  --seed-scheduler round-robin --max-iterations 10000
```

| Поле | Допустимые значения / смысл |
| --- | --- |
| profile | legacy (default), mutation-only, hybrid-heuristic, hybrid-ml |
| seed_scheduler.type | random (default), round-robin |
| strategy_policy.type | legacy, stagnation, contextual_bandit; соответствует профилю |
| strategy_policy.epsilon | Вероятность исследования bandit, [0, 1], default 0.1 |
| strategy_policy.learning_rate | Коэффициент обновления bandit, (0, 1], default 0.1 |
| stages[].type | deterministic, mutation, i2s, i2s_smt |
| mutation.mutator | havoc, bitflip, byteflip |
| mutation.operators | Необязательный непустой список операторов havoc в заданном порядке |
| i2s/i2s_smt.binding | value_match |
| i2s_smt.solver | z3 |
| i2s_smt.timeout_ms | Положительный таймаут; дополнительно ограничивается остатком wall-time |
| allow_incomplete | Политика частичных сравнений; default true для legacy SMT, false для новых гибридов |
| admission.type | coverage_novelty; потребляет Go new_edges, не создаёт второй frontier |

Имена операторов havoc: flip1, flip2, flip4, byte, arith8, arith16, arith32,
interesting8, interesting16, interesting32, insert, duplicate, delete.
Отсутствующий список означает всё legacy-меню; пустой список и повторы — ошибка.
Выбор оператора и stacking имеют отдельные C++-контракты; стандартный выбор
равномерный, stacking — прежняя степень двойки до 128 операций.

Секция campaign: max_iterations (0 = без лимита), max_seconds (0 = без wall
лимита), metrics_interval, max_det_steps, run_seeds_first, stagnation_threshold,
min_exec_interval, adaptive_throttle. Для прежних исследований сохраняются
fix_findfirst_index, fix_addvars, fix_writeback_width и system_form (0/1/2).
Лимит запросов проверяется и между подготовительным запуском и кандидатом.
Сервис не копируется; политика видит только снимок BudgetView. Wall-time
ограничивает начало следующего исполнения и работу построения/солвера;
уже начатый Run имеет прежний таймаут сервера. CPU-бюджета нет.

Legacy сохраняет det-first, RNG и прежний смысл подготовительного запуска.
Round-robin действует на выборе сида после det-first. В новых профилях
подготовка тоже может приносить наблюдаемое покрытие или finding, но уже
имеющийся сид не дублируется в corpus. Mutation-only не включает ни I2S,
ни SMT. Общие генераторы обоих гибридов одинаковы; различается политика.
Hybrid-ml — экспериментальный онлайн epsilon-greedy по двум признакам
(размер входа, стагнация), с шестью действиями: mutation, I2S, SMT с бюджетами
1/10/100/1000 мс в пределах конфига. Награда зависит от исполнений, а не SAT.
Необязательные действия маскируются при недостатке бюджета/наблюдений.
Обученная внешняя модель, восстановление её checkpoint и научный выигрыш
этой конфигурацией не обещаются.

В out-dir сохраняются:

- `resolved.yaml`: раскрытая композиция, включая seed, лимиты и параметры.
- `run-manifest.yaml`: ревизия, run_id, target/argv, capabilities и версии модулей.
- `events.jsonl`: решения, все попытки исполнения, исходы, wall/CPU процесса
  контроллера. CPU цели и Go-сервера этим таймером не измеряется.

Журнал v1 использует числовые enum: stage 0=deterministic, 1=mutation, 2=i2s,
3=i2s_smt; outcome 0=candidate, 1=exhausted, 2=not_applicable, 3=no_binding,
4=unsat, 5=timeout, 6=solver_error, 7=infrastructure_error, 8=cancelled.
Локальный run_id уникален в кампании; transport_run_id — отдельный номер
ответа сервера (0 при отсутствии ответа). Decision содержит локальный лимит,
таймаут, индекс действия и контекст. Кандидат не считается исполненным по
самому факту генерации. Серверный new_edges, допуск в corpus и награда —
разные величины.

comparisons_available сообщает о наличии собранного снимка для этого запуска;
comparisons_complete — о его полноте. По умолчанию сравнения копируются только
для RunPurpose comparisons (2), а не после каждой мутации. Отсутствие сбора
не является переполнением; allow_incomplete не разрешает отсутствующие
наблюдения. Legacy-счётчики неуспешной подготовки сохраняют прежний смысл.

## Сборка модулей

```bash
# Mutation + дешёвая I2S, без Z3.
cmake -B build -DFUZZER_BUILD_Z3=OFF -DFUZZER_ENABLE_SMT=OFF -DFUZZER_ENABLE_I2S=ON
# Только mutation/deterministic.
cmake -B build -DFUZZER_BUILD_Z3=OFF -DFUZZER_ENABLE_SMT=OFF -DFUZZER_ENABLE_I2S=OFF
```

FUZZER_ENABLE_SMT управляет регистрацией стадии независимо от наличия
исследовательской солверной библиотеки. Если он включён, нужен BUILD_Z3.
Для гибрида без SMT нужно явно удалить i2s_smt из YAML либо передать
--no-concolic. Отключение SMT не отключает трассировку сравнений у цели:
нынешний CLI всё ещё ожидает два канала от Go. Coverage-only требует
отдельной согласованной миграции протокола/конфигурации инструментации.
