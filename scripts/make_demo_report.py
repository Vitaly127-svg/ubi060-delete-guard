"""Create a readable report from an actual HTTP demonstration result."""
import argparse
import html
import json
from datetime import datetime
from pathlib import Path


LABELS = {
    "login owner": "Вход владельца данных",
    "login admin": "Вход администратора",
    "read available dataset": "Чтение доступного набора",
    "quarantine": "Разрешённое удаление: перевод в карантин",
    "idempotent retry": "Повтор запроса: прежний результат без второго удаления",
    "quarantined data hidden": "Карантинный набор скрыт от чтения",
    "restore": "Восстановление набора владельцем",
    "restored data readable": "Восстановленный набор снова читается",
    "R5 reference protected": "Удаление справочника со ссылками отложено",
    "R2 tampered policy blocked": "Изменённая политика хранения заблокирована",
    "purge fixture quarantined": "Второй набор помещён в карантин для окончательного удаления",
    "purged data unavailable": "После срока карантина удалённый набор недоступен",
    "audit chain": "Проверка целостности цепочки журнала",
}


def render(report, source):
    steps = report["steps"]
    passed = bool(steps) and report.get("all_passed") is True and all(
        s.get("ok") is True and s["status"] == s["expected"] for s in steps)
    local = report["mode"] == "local-http-sqlite"
    mode = ("Локальный запуск: пять HTTP-сервисов Python и SQLite." if local else
            "Кластерный запуск через HTTPS-шлюз: Kubernetes, PostgreSQL, Cassandra и RabbitMQ.")
    scope = ("Этот режим показывает выполнение функций через HTTP. NGINX, Cassandra, RabbitMQ "
             "и сетевые политики проверяются отдельным сценарием Kubernetes smoke test в GitHub Actions."
             if local else "Результаты получены сценарием обращений через NGINX в тестовом кластере.")
    rows = []
    for i, step in enumerate(steps, 1):
        ok = step.get("ok") is True and step["status"] == step["expected"]
        label = html.escape(LABELS.get(step["step"], step["step"]))
        rows.append(f'<tr><td>{i}</td><td>{label}</td><td>{int(step["status"])}</td>'
                    f'<td>{int(step["expected"])}</td><td class="{"ok" if ok else "fail"}">'
                    f'{"Пройдено" if ok else "Ошибка"}</td></tr>')
    title = "Все проверки пройдены" if passed else "Есть непройденные проверки"
    stamp = datetime.fromtimestamp(source.stat().st_mtime).astimezone().strftime("%d.%m.%Y %H:%M:%S %z")
    return f'''<!doctype html>
<html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Демонстрация контролируемого удаления</title>
<style>
body{{font:17px/1.5 system-ui,sans-serif;color:#182536;background:#f0f3f7;margin:0;padding:32px}}
main{{max-width:1100px;margin:auto;background:white;padding:32px;border-radius:12px}}
h1{{font-size:30px;margin-top:0}}h2{{font-size:24px}}p{{max-width:950px}}
table{{width:100%;border-collapse:collapse;font-size:15px}}th,td{{padding:12px;border-bottom:1px solid #d6dfe8;text-align:left}}
th{{background:#eef3f8}}.ok{{color:#176b39;font-weight:650}}.fail{{color:#b32020;font-weight:650}}
footer{{margin-top:24px;font-size:14px;color:#526172}}
@media(max-width:700px){{body,main{{padding:12px}}table{{font-size:12px}}th,td{{padding:6px}}}}
</style><main>
<h1>Контролируемое удаление данных при угрозе УБИ.060</h1>
<p>{mode} Время результата: {stamp}.</p>
<h2 class="{"ok" if passed else "fail"}">{title}</h2>
<p>Выполнено шагов: {len(steps)}. Сформировано уведомлений: {int(report["notification_count"])}.</p>
<p>Коды 403, 409 и 410 являются ожидаемыми результатами защитных проверок, когда они совпадают со столбцом «Ожидаемый код».</p>
<table><thead><tr><th>№</th><th>Проверяемое действие</th><th>Полученный код</th><th>Ожидаемый код</th><th>Результат</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table>
<p>{scope}</p>
<footer>Отчёт сформирован из фактического результата {html.escape(source.name)}.
После автоматического сценария локальные сервисы останавливаются. Для нового показа снова запустите START_DEMO.cmd.</footer>
</main></html>'''


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, default=Path("artifacts/local-smoke.json"))
    parser.add_argument("--output", type=Path, default=Path("artifacts/demo-report.html"))
    args = parser.parse_args()
    report = json.loads(args.input.read_text(encoding="utf-8"))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(render(report, args.input), encoding="utf-8")
    print(args.output.resolve())
