import type { NodeMode, NodeStatus } from "../api/types";

export const NODE_STATUS_LABEL: Record<NodeStatus, string> = {
  online: "На связи",
  offline: "Нет связи",
  never: "Ещё не подключался",
  disabled: "Отключён",
  autonomous: "Автономный",
};

export const NODE_STATUS_PILL: Record<NodeStatus, string> = {
  online: "pill-ok",
  offline: "pill-danger",
  never: "pill-warn",
  disabled: "pill-muted",
  autonomous: "pill-info",
};

export const NODE_MODE_LABEL: Record<NodeMode, string> = {
  online: "Сетевой",
  offline: "Автономный",
};

/** Строки вида «10.1.0.0/24, 10.2.0.1-10.2.0.9» или по одной на строке. */
export function splitScope(text: string): string[] {
  return text
    .split(/[\s,;]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

/** Адрес центра без TLS, который узел не примет без SCANNER_NODE_ALLOW_HTTP=1 (localhost — можно). */
export function needsAllowHttp(server: string): boolean {
  let url: URL;
  try {
    url = new URL(server);
  } catch {
    return false;
  }
  if (url.protocol !== "http:") return false;
  return !["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
}

/** Содержимое .env.node для сетевого узла (docker-compose.node.yml). */
export function nodeEnv(server: string, token: string, scope: string[]): string {
  return [
    `SCANNER_NODE_SERVER=${server}`,
    `SCANNER_NODE_TOKEN=${token}`,
    `SCANNER_NODE_ALLOWLIST=${scope.join(",")}`,
  ].join("\n");
}
