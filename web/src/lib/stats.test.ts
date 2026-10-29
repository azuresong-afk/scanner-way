import { finding } from "../test/fixtures";
import { applyFilter, byHost, emptyFilter, findingKey, heatLevel, inventoryRows, replaceFinding, summarize } from "./stats";

describe("summarize", () => {
  it("считает открытые, новые, регрессии, закрытые и долю БДУ", () => {
    const prev = [
      finding({ host: "10.0.0.1", vuln_id: "CVE-1", severity: "critical" }),
      finding({ host: "10.0.0.2", vuln_id: "CVE-2", severity: "medium" }),
      finding({ host: "10.0.0.3", vuln_id: "INFO", severity: "info" }),
    ];
    const cur = [
      finding({ host: "10.0.0.1", vuln_id: "CVE-1", severity: "critical", status: "open" }),
      finding({ host: "10.0.0.4", vuln_id: "CVE-3", severity: "high", status: "new", bdu_ids: [] }),
      finding({ host: "10.0.0.5", vuln_id: "CVE-4", severity: "low", status: "regression" }),
      finding({ host: "10.0.0.5", vuln_id: "INFO", severity: "info", module: "discovery", cve_ids: [], bdu_ids: [] }),
    ];
    const s = summarize(cur, prev);
    expect(s.open).toBe(3);
    expect(s.counts.critical).toBe(1);
    expect(s.counts.info).toBe(1);
    expect(s.newCount).toBe(1);
    expect(s.regression).toBe(1);
    expect(s.fixed).toBe(1); // CVE-2 на 10.0.0.2 исчезла; info не считается
    expect(s.prevOpen).toBe(2);
    expect(s.bduShare).toBeCloseTo(2 / 3);
    expect(s.hosts).toBe(3);
  });

  it("без предыдущего прогона не считает закрытые", () => {
    const s = summarize([finding()]);
    expect(s.fixed).toBe(0);
    expect(s.prevOpen).toBeNull();
  });
});

describe("byHost", () => {
  it("сортирует хосты по риску и собирает сервисы", () => {
    const rows = byHost(
      [
        finding({ host: "10.0.0.9", severity: "medium" }),
        finding({ host: "10.0.0.2", severity: "critical" }),
        finding({ host: "10.0.0.2", severity: "low", vuln_id: "X" }),
      ],
      [{ host: "10.0.0.2", port: 22, protocol: "tcp", service: "ssh", product: "OpenSSH", version: "7.4", cpe: null }],
    );
    expect(rows.map((r) => r.host)).toEqual(["10.0.0.2", "10.0.0.9"]);
    expect(rows[0].maxSeverity).toBe("critical");
    expect(rows[0].total).toBe(2);
    expect(rows[0].summary).toBe("OpenSSH 7.4");
  });

  it("сортирует IP численно", () => {
    const rows = byHost([finding({ host: "10.0.0.10", severity: "low" }), finding({ host: "10.0.0.9", severity: "low" })]);
    expect(rows.map((r) => r.host)).toEqual(["10.0.0.9", "10.0.0.10"]);
  });
});

describe("inventoryRows", () => {
  const inv = [
    { host: "10.0.0.10", os_guess: null, run_ids: [1], services_run_id: 1, services: [], packages_run_id: null, package_count: 0 },
    { host: "10.0.0.9", os_guess: null, run_ids: [1, 2], services_run_id: 2, services: [], packages_run_id: null, package_count: 0 },
  ];

  it("сохраняет порядок по IP и берёт счётчики из прогона", () => {
    const rows = inventoryRows(inv, [finding({ host: "10.0.0.10", severity: "critical" }), finding({ host: "10.0.0.10", severity: "info", vuln_id: "I" })], 1);
    expect(rows.map((r) => r.host)).toEqual(["10.0.0.9", "10.0.0.10"]);
    expect(rows[1].total).toBe(1);
    expect(rows[1].maxSeverity).toBe("critical");
    expect(rows[0].total).toBe(0);
    expect(rows.every((r) => r.inRun)).toBe(true);
  });

  it("отмечает хосты, которых не было в прогоне", () => {
    const rows = inventoryRows(inv, [], 2);
    expect(rows.find((r) => r.host === "10.0.0.10")).toMatchObject({ inRun: false, lastRunId: 1 });
    expect(rows.find((r) => r.host === "10.0.0.9")?.inRun).toBe(true);
  });
});

describe("applyFilter", () => {
  const list = [
    finding({ severity: "critical", module: "vuln", title: "Log4j" }),
    finding({ severity: "medium", module: "config_audit", title: "SSH root login", bdu_ids: [], cve_ids: [], vuln_id: "CIS-5.2" }),
    finding({ severity: "low", module: "vuln", status: "new", host: "10.1.1.1" }),
  ];
  it("фильтрует по опасности, модулю, статусу, БДУ и тексту", () => {
    expect(applyFilter(list, { ...emptyFilter(), severities: ["critical"] })).toHaveLength(1);
    expect(applyFilter(list, { ...emptyFilter(), modules: ["config_audit"] })).toHaveLength(1);
    expect(applyFilter(list, { ...emptyFilter(), statuses: ["new"] })).toHaveLength(1);
    expect(applyFilter(list, { ...emptyFilter(), bduOnly: true })).toHaveLength(2);
    expect(applyFilter(list, { ...emptyFilter(), query: "bdu:2021-05969" })).toHaveLength(2);
    expect(applyFilter(list, { ...emptyFilter(), query: "10.1.1.1" })).toHaveLength(1);
  });
});

it("findingKey совпадает для одной находки в разных прогонах", () => {
  expect(findingKey(finding({ status: "new" }))).toBe(findingKey(finding({ status: "open", cvss: 1 })));
});

it("heatLevel ступени", () => {
  expect([0, 1, 2, 3, 4, 6, 7, 50].map(heatLevel)).toEqual([0, 1, 2, 2, 3, 3, 4, 4]);
});

describe("ложные срабатывания", () => {
  const fp = { reason: null, marked_by: "op", marked_at: null };

  it("не входят в счётчики, хосты и закрытые", () => {
    const prev = [finding({ id: 1, vuln_id: "CVE-1", false_positive: fp }), finding({ id: 2, vuln_id: "CVE-2" })];
    const cur = [finding({ id: 3, vuln_id: "CVE-1", false_positive: fp, severity: "critical" }), finding({ id: 4, vuln_id: "CVE-2" })];
    const s = summarize(cur, prev);
    expect(s.open).toBe(1);
    expect(s.counts.critical).toBe(0);
    expect(s.fixed).toBe(0);
    expect(s.prevOpen).toBe(1);
    expect(byHost(cur)[0].total).toBe(1);
  });

  it("replaceFinding подменяет находку по id", () => {
    const list = [finding({ id: 1 }), finding({ id: 2 })];
    const out = replaceFinding(list, finding({ id: 2, false_positive: fp }));
    expect(out.map((f) => !!f.false_positive)).toEqual([false, true]);
  });
});
