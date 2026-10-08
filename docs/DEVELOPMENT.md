# Сборка и проверка

## Требования

Текущие LLVM-проходы требуют **LLVM 20** и совместимого `clang-20`.
Общее обозначение «LLVM 17+» в старых планах не является требованием этой
сборки. Нужны CMake 3.25+, Ninja, компилятор C++20, Git и Python 3.
Go-модуль задаёт `go 1.23` и `toolchain go1.24.2`; при необходимости Go
попытается получить этот toolchain. Для линта нужны clang-format,
clang-tidy и golangci-lint. `scripts/bootstrap.sh` только проверяет инструменты.

Z3 зафиксирован подмодулем. Protobuf, Abseil, spdlog, yaml-cpp,
tl::expected и GoogleTest получаются через CMake. Начальная настройка
требует доступа к источникам зависимостей. Версии — в
[перечне зависимостей](DEPENDENCIES.md).

## Сборка C++ и тестов

Из корня клона:

```sh
git submodule update --init --recursive
CC=clang-20 CXX=clang++-20 cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j4
ctest --test-dir build --output-on-failure
```

Debug включает `-Wall -Wextra -Wpedantic -Werror` для кода проекта.
Зависимости не наследуют эти предупреждения. Полный набор интеграционных
тестов содержит длительные измерения; время проверки зависит от машины.

## Сервер исполнения

```sh
cd exec-server
go build ./...
go vet ./...
go test ./...
```

Для отдельного бинаря из корня:

```sh
go -C exec-server build -o ../build/exec-server-bin ./cmd/exec-server
```

CLI описывает доступные параметры через `build/src/cli/fuzzer --help`.
Цель должна быть инструментирована; наличие произвольного исполняемого
файла не означает наличие обратной связи покрытия.

## Форматирование и статический анализ

```sh
./scripts/format.sh --check
BUILD_DIR=build ./scripts/lint.sh
./scripts/ci.sh --no-clean
```

Полный CI выполняет сборку, CTest, Go build/vet/test, форматирование и линт.
Без `--no-clean` он удаляет прежний каталог сборки перед запуском.
Результат проверки этого среза и её ограничения — [VALIDATION.md](VALIDATION.md).
