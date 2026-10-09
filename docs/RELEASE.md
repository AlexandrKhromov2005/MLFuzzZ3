# Состав для переноса

Этот репозиторий имеет собственную историю и одну ветку `main`.
Зависимость Z3 сохраняется как подмодуль с фиксированной ревизией.
Документация проекта и отчёты написаны на русском; сообщения коммитов —
на английском в формате Conventional Commits.

Перед публикацией требуется полный успешный прогон проверки в окружении,
которое поддерживает операции IPC, и получение зависимостей без заранее
подготовленного кэша. Текущий статус — [VALIDATION.md](VALIDATION.md).

## Перенос истории

Из предоставленного bundle можно создать рабочую копию:

```sh
git clone --branch main MLFuzzZ3-public.bundle MLFuzzZ3
cd MLFuzzZ3
git remote remove origin
git submodule update --init --recursive
```

Публичный репозиторий: [AlexandrKhromov2005/MLFuzzZ3](https://github.com/AlexandrKhromov2005/MLFuzzZ3).
Для отправки основной ветки указывается точная пара ссылок:

```sh
git remote add origin https://github.com/AlexandrKhromov2005/MLFuzzZ3.git
git push origin refs/heads/main:refs/heads/main
```

Архив исходников является альтернативой bundle, но не содержит историю Git.
Подмодуль Z3 в архив не вложен: для такого варианта его нужно получить
на ревизии из [DEPENDENCIES.md](DEPENDENCIES.md).
