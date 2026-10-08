# Зависимости сборки

Z3 — подмодуль, ревизия `ddb49568d3520e99799e364fb22f35fc67d887b1`.
CMake фиксирует прямые зависимости тегами в `CMakeLists.txt`.
Ниже ревизии локального кэша проверки; это не проверка загрузки из сети.

| Зависимость | Ревизия кэша |
| --- | --- |
| protobuf | `4b0c3aacf0657fbf38253b38918d3358dd4319ec` |
| absl | `76bb24329e8bf5f39704eb10d21b9a80befa7c81` |
| spdlog | `79524ddd08a4ec981b7fea76afd08ee05f83755d` |
| yaml-cpp | `56e3bb550c91fd7005566f19c079cb7a503223cf` |
| tl-expected | `292eff8bd8ee230a7df1d6a1c00c4ea0eb2f0362` |
| googletest | `52eb8108c5bdec04579160ae17225d66034bd723` |

Версии Go-модулей: `exec-server/go.mod` и `exec-server/go.sum`.
Go toolchain задаётся в `go.mod`. LLVM-проходы требуют LLVM 20.
У сторонних зависимостей собственные лицензии; MIT проекта не меняет их условия.
