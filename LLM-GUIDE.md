# mesh-debug: Инструкция для LLM-агента

`mesh-debug` — детерминированная CLI-утилита диагностики **Istio Ambient Mesh + Kube-OVN + MetalLB** для чартов `ingress-gateway`, `egress-gateway` и `policies` (ЕЦПК / ACP).

## Базовый workflow для LLM

1. **Всегда начинай с read-only прогона в формате JSON** (безопасно, не создаёт подов в кластере):
   - Проблема с входящим трафиком (`ingress-gateway` — Gateway, MetalLB VIP / `IPAddressPool`, `externalTrafficPolicy`, TLS, Routes, ReferenceGrant, NP/AP с учётом `podSelector`/`selector`, Envoy/ztunnel):
     ```bash
     mesh-debug ingress -n <namespace> --format json
     # или конкретный Gateway:
     mesh-debug ingress -n <namespace> <gateway-name> --format json
     ```
   - Проблема с исходящим трафиком (`egress-gateway`, режимы `mesh` и `direct`; можно передать **любой** из 3 неймспейсов — senders, waypoint или VEG; проверяет в т.ч. Kube-OVN `externalSubnet`/`externalIPs` IPAM, `AcquireAddressFailed: AddressOutOfRange`, рассинхрон селекторов VEG и shared-waypoint VIP коллизии):
     ```bash
     mesh-debug egress -n <namespace> --format json
     ```
   - Карта связей и проверка политик для **любого пода / оператора / гейтвея** (`policies` — определяет `ServiceAccount`/principal, ноду и её `ztunnel`-под, тип workload'а, разбирает логи `ztunnel`, RBAC операторов, webhooks, маршруты и оценивает каждый хоп: `Src Egress NP` → `Src ztunnel` → `Dst Ingress NP` → `Dst PeerAuthentication` → `Dst ztunnel` → `Dst AuthorizationPolicy`):
     ```bash
     mesh-debug policies -n <namespace> <pod|deploy/name|sts/name|gw/name> --format json
     # What-if симуляция конкретного пути (без живого трафика):
     mesh-debug policies -n <namespace> <pod|deploy/name> --to kube-apiserver --to other-ns/svc:8080 --format json
     # Генерация черновика values.yaml для чарта console-charts/policies (read-only по наблюдаемым/симулированным связям):
     mesh-debug policies -n <namespace> deploy/<name> --emit-policies --format yaml
     ```
   - Проверить только ztunnel и перехват подов в namespace:
     ```bash
     mesh-debug ztunnel -n <namespace> --format json
     ```
   - Общая проверка control plane / OVN / Kyverno / MetalLB `IPAddressPool`:
     ```bash
     mesh-debug status --format json
     ```

2. **Активные режимы (создают временный под `debug-toolbox` с автоудалением — запускать, если read-only `HEALTHY` или нужно поймать живые попытки соединений):**
   - Активные сетевые пробы (`--probe` для `ingress` / `egress` — loopback `127.0.0.1`, DNS, VIP, TLS handshake):
     ```bash
     mesh-debug ingress -n <namespace> --probe --format json
     mesh-debug egress  -n <namespace> --probe --format json
     # Если выход в интернет идёт через корпоративный прокси:
     mesh-debug egress  -n <namespace> --probe --proxy http://10.192.95.164:8090 --format json
     ```
   - Живой перехват попыток соединений пода (`--capture` для `policies` — ловит TCP `SYN` + `UDP`, включая заблокированные `SYN`, non-mesh поды, операторы и distroless):
     ```bash
     # По умолчанию используется --capture-mode node (временный privileged+hostPID под в --capture-ns default,
     # работает в PodSecurity baseline/restricted и не мутирует целевой под):
     mesh-debug policies -n <namespace> <pod|deploy/name> --capture 30s --format json
     # Живой перехват + генерация values.yaml для чарта policies:
     mesh-debug policies -n <namespace> <pod|deploy/name> --capture 30s --emit-policies --format yaml
     # Если нужен ephemeral container вместо node-capture (только в privileged namespace):
     mesh-debug policies -n <namespace> <pod> --capture 30s --capture-mode ephemeral --format json
     ```
   > Временные поды создаются с ResourceQuota-безопасными `requests`/`limits` и удаляются автоматически после завершения.

3. **Коды возврата:**
   - `0` — `HEALTHY` или `DEGRADED` (нет `FAIL`-проверок)
   - `1` — ошибка аргументов/запуска
   - `2` — `BROKEN` (найдена хотя бы одна `FAIL`-проверка)

## Структура JSON-отчёта

```json
{
  "tool": "mesh-debug",
  "command": "ingress|egress|ztunnel|policies|status",
  "namespace": "...",
  "target": "...",
  "mode": "mesh|direct|workload|operator|ingress-gateway|waypoint",
  "probe_mode": false,
  "metadata": {
    "ztunnel_namespace": "ztunnel",
    "ztunnel_pod": "ztunnel/ztunnel-xxxx",
    "service_account": "...",
    "principal": "cluster.local/ns/.../sa/...",
    "policies_values_yaml": "(при --emit-policies)"
  },
  "summary": { "total": 18, "pass": 15, "warn": 1, "fail": 2, "verdict": "BROKEN" },
  "checks": [
    {
      "id": "stable-check-id",
      "layer": "Control Plane | Target & Identity | Gateway & Infrastructure | TLS & Certificates | Routes & Backends | Policies | ServiceEntries & VIPs | Waypoint & Envoy | Kube-OVN & VEG Runtime | Packet Capture | Traffic Map & Policy Verdict | Generated Policies Values | Logs & ztunnel | Active Probes",
      "title": "...",
      "status": "PASS | WARN | FAIL | INFO | SKIP",
      "resource": "ns/name",
      "message": "краткий диагноз",
      "details": ["..."],
      "evidence": ["выдержки логов / событий / правил / пулов / подсетей"],
      "suggestion": "конкретное действие для исправления"
    }
  ],
  "next_actions": ["приоритизированный список действий (сначала FAIL, потом WARN)"],
  "commands": ["точные выполненные команды при флаге --verbose"]
}
```

## Особенности интерпретации для LLM

- **`ingress` / `externalTrafficPolicy: Local`**: выдаётся как `WARN` (`gw-svc-etp-*`, вердикт `DEGRADED`). Стандарт платформы — `Cluster`; при `Local` внешний трафик работает, но обращения к VIP из подов внутри кластера с нод без пода гейтвея падают по timeout.
- **`ingress` / MetalLB `not allowed in config`**: в `evidence` проверки `gw-vip-*` уже перечислены событие `AllocationFailed` и все `IPAddressPool` кластера (диапазоны и `serviceAllocation`).
- **`egress` / Kube-OVN `AddressOutOfRange`**: проверяй `veg-ext-ip-*`, `veg-ext-subnet-missing`, `veg-pod-ipam-*` и `veg-selector-mismatch` (когда VEG вместо waypoint целится напрямую в sender namespace).
- **`policies` / операторы и `kube-apiserver`**: Kube-OVN `NetworkPolicy` фильтрует **после DNAT** — нужны IP control-plane нод на порт **`6443/TCP`** (а не `ClusterIP:443`). При `--emit-policies` системный egress (`kube-apiserver:6443`, `kube-system` CoreDNS, `istio-system` istiod) намеренно выносится в `netpol[]`, чтобы чарт `policies` не создавал зеркала в системных namespace.

## Как отвечать пользователю

1. Начни с итогового вердикта (`summary.verdict`) и списка всех `FAIL` (затем важных `WARN`) по слоям.
2. Опирайся **только на `evidence`, `details` и `message` из JSON** — не додумывай ресурсы или логи.
3. Приведи конкретные рекомендации из `next_actions` (а при `--emit-policies` — сгенерированный `values.yaml` с пометкой, что это черновик по наблюдаемому окну и редкие/cron-связи стоит перепроверить).
4. Если все read-only проверки зелёные, а трафик всё равно не ходит — предложи (или выполни, если разрешено) запуск с `--probe` / `--capture 30s` либо точечную проверку по порядку `ambient-check`.
