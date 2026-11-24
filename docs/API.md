# API

Все методы отдают JSON, кроме `subscribe.txt`. Ошибки — `{"error": "..."}` с HTTP-статусом.

## Прокси

| Метод | Путь | Описание |
|-------|------|----------|
| GET | `/api/proxies?filter=&source=&search=&reason=&limit=&offset=` | Список прокси с пагинацией; `reason` — причина отказа failed |
| GET | `/api/status` | Статистика: total, working, failed, top_speed, источники, причины |
| GET | `/api/countries` | Страны, проверка, blocked-статус и `no_country` |
| GET | `/api/test-progress` | Статус прогона: стадии, счётчики, текущий профиль |
| GET | `/api/test-progress/stream` | SSE-поток прогресса |
| POST | `/api/test-cancel` | Отменить текущий прогон |
| POST | `/api/add` | Добавить `{"link": "vless://..."}`; тест стартует, если нет другого замера |
| POST | `/api/test/<id>` | Полный тест одного прокси; `speed` — средняя, `speed_max` — пик. Тело JSON опционально: `{"speed_url": "http://…"}` — проверить конкретный файл замера через этот профиль; в ответе `speed_error` — причина, если скорость не измерилась |
| POST | `/api/test-all` | Поэтапный конвейер по всем прокси |
| GET | `/api/performance/recommendations` | Оценка длительности прогона и фактические стадии |
| DELETE | `/api/delete/<id>` | Удалить прокси |
| POST | `/api/cleanup` | Удалить все failed |
| POST | `/api/proxies/batch-delete` | Удалить выбранные `{"ids": [1,2,3]}` |
| POST | `/api/proxies/batch-test` | Проверить выбранные |
| POST | `/api/test-failed` | Перетест только failed |

## Источники

| Метод | Путь | Описание |
|-------|------|----------|
| GET | `/api/sources` | Источники: счётчики, итог импорта, счётчики последнего импорта, оценка, вердикт |
| POST | `/api/sources` | Добавить URL-источник `{"name":"...","url":"..."}` |
| POST | `/api/sources/txt` | Добавить TXT-источник `{"name":"...","content":"vless://..."}` |
| DELETE | `/api/sources/<id>` | Удалить источник |
| GET/PUT | `/api/sources/<id>/content` | Прочитать/обновить TXT-контент |
| POST | `/api/sources/<id>/import` | Импорт; статус, причина, added/duplicates/parsed |
| POST | `/api/sources/import-all` | Импорт всех с бюджетом времени и отчётом `results` |
| GET | `/api/config/preview?limit=` | Что попадёт в конфиг и подписку: `selected`, `excluded`, `fallback`, `settings` |
| POST | `/api/refresh-stale` | Актуализация устаревших и незамеренных |
| GET | `/api/import/diagnose?url=&source_id=&timeout=` | DNS → TCP → TLS → HTTP; без параметров — все URL-источники |

## URL проверки и файла замера

| Метод | Путь | Описание |
|-------|------|----------|
| GET | `/api/urls/candidates` | Текущие URL и каталоги кандидатов (probe/speed), последний тест, авто-режим |
| GET/POST | `/api/urls/test` | Тест лучших ссылок: `kind=probe\|speed\|all`, `apply` (по умолчанию true), `timeout`, `urls` — свои кандидаты. Возвращает `results`, `best`, `applied`; для `all` — два отчёта |

## Xray, настройки, подписка

| Метод | Путь | Описание |
|-------|------|----------|
| GET | `/api/xray/status` | Статус Xray: running, API, systemd, outbounds, `socks_port`/`http_port`/`api_port` |
| GET | `/api/xray/outbounds` | Outbound и трафик по узлам |
| POST | `/api/xray/start`, `/api/xray/stop`, `/api/xray-restart` | Управление через systemd |
| POST | `/api/xray/rebuild` | Пересобрать конфиг и применить |
| GET/POST | `/api/settings` | Все настройки / сохранить с валидацией |
| GET | `/api/performance/recommendations` | Оценка прогона: пачка, префильтр (воркеры/повторы), этапы последнего прогона |
| GET | `/api/backup` | Экспорт настроек и источников |
| POST | `/api/backup/import` | Импорт настроек и источников |
| GET/POST | `/api/geosite-rules` | GeoSite-правила |
| GET | `/api/subscribe.txt` | Подписка для клиентов |
| GET | `/api/logs?limit=&offset=&level=` | Логи; `level` — один уровень или список `WARN,ERROR` |
| POST | `/api/logs/clear` | Очистить логи |
| GET | `/api/connections/list` | Активные TCP-соединения |
| GET | `/api/connections/traffic` | Трафик по IP клиента |
| POST | `/api/connections/close` | Закрыть соединение `{"remote_host","remote_port"}` |
| POST | `/api/connections/flush` | Закрыть все соединения |
| GET | `/api/health` | Health check для systemd/monitoring |

Порты Xray (`socks_port`, `http_port`, `api_port`) — обычные настройки: их можно
менять через `POST /api/settings`, но порты должны различаться, а после смены
нужен перезапуск Xray (они входят в конфиг inbounds и API).
