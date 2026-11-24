# mesh-debug: Инструкция для LLM-агента

`mesh-debug` — детерминированная CLI-утилита диагностики **Istio Ambient Mesh + Kube-OVN** для чартов `ingress-gateway` и `egress-gateway` (ЕЦПК / ACP).

## Базовый workflow для LLM

1. **Всегда начинай с read-only прогона в формате JSON** (безопасно, не создаёт подов в кластере):
   - Проблема с входящим трафиком (`ingress-gateway`):
     ```bash
     mesh-debug ingress -n <namespace> --format json
     # или конкретный Gateway:
     mesh-debug ingress -n <namespace> <gateway-name> --format json
     ```
   - Проблема с исходящим трафиком (`egress-gateway`, режимы `mesh` и `direct`; можно передать **любой** из 3 неймспейсов — senders, waypoint или VEG):
     ```bash
     mesh-debug egress -n <namespace> --format json
     ```
   - Проверить только ztunnel и перехват подов в namespace:
     ```bash
     mesh-debug ztunnel -n <namespace> --format json
     ```
   - Карта связей и проверка NetworkPolicy / AuthorizationPolicy / PeerAuthentication / ztunnel для любого пода (workload, оператор, ingress, waypoint) + симуляция `--to` и генерация `values.yaml` для чарта `policies`:
     ```bash
     mesh-debug policies -n <namespace> <pod|deploy/name> --format json
     mesh-debug policies -n <namespace> <pod> --to kube-apiserver --to other-ns/svc:8080 --format json
     mesh-debug policies -n <namespace> <pod> --capture 30s --emit-policies --format yaml
     ```
   - Общая проверка control plane / OVN / Kyverno:
     ```bash
     mesh-debug status --format json
     ```

2. **Если read-only проверки `HEALTHY` или нужно проверить живой сетевой путь (DNS, VIP, TLS handshake, loopback 127.0.0.1)** — запусти активные пробы с `--probe`:
   ```bash
   mesh-debug ingress -n <namespace> --probe --format json
   mesh-debug egress  -n <namespace> --probe --format json
   # Если выход в интернет идёт через корпоративный прокси:
   mesh-debug egress  -n <namespace> --probe --proxy http://10.192.95.164:8090 --format json
   ```
   > Утилита сама создаст временный под `debug-toolbox` с ResourceQuota-безопасными `requests`/`limits`, выполнит `curl`/`dig`/`nc` и удалит его после завершения.

3. **Коды возврата:**
   - `0` — `HEALTHY` или `DEGRADED` (нет `FAIL`-проверок)
   - `1` — ошибка аргументов/запуска
   - `2` — `BROKEN` (найдена хотя бы одна `FAIL`-проверка)

## Структура JSON-отчёта

```json
{
  "tool": "mesh-debug",
  "command": "ingress|egress|ztunnel|status",
  "namespace": "...",
  "mode": "mesh|direct",
  "probe_mode": false,
  "metadata": { "ztunnel_namespace": "ztunnel", "...": "..." },
  "summary": { "total": 18, "pass": 15, "warn": 1, "fail": 2, "verdict": "BROKEN" },
  "checks": [
    {
      "id": "stable-check-id",
      "layer": "Gateway & Infrastructure | TLS & Certificates | Routes & Backends | Policies | ServiceEntries & VIPs | Waypoint & Envoy | Kube-OVN & VEG Runtime | Logs & ztunnel | Active Probes",
      "title": "...",
      "status": "PASS | WARN | FAIL | INFO | SKIP",
      "resource": "ns/name",
      "message": "краткий диагноз",
      "details": ["..."],
      "evidence": ["выдержки логов / правил / VIP"],
      "suggestion": "конкретное действие для исправления"
    }
  ],
  "next_actions": ["приоритизированный список действий (сначала FAIL, потом WARN)"],
  "commands": ["точные выполненные команды при флаге --verbose"]
}
```

## Как отвечать пользователю

1. Начни с итогового вердикта (`summary.verdict`) и списка всех `FAIL` (затем важных `WARN`) по слоям.
2. Опирайся **только на `evidence` и `message` из JSON** — не додумывай ресурсы или логи.
3. Приведи конкретные рекомендации из `next_actions`.
4. Если все read-only проверки зелёные, а трафик всё равно не ходит — предложи (или выполни, если разрешено) запуск с `--probe` либо точечную проверку по порядку `ambient-check`.
