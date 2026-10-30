import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { SoftwareTable } from "./SoftwareTable";
import { finding } from "../test/fixtures";
import { bySoftware } from "../lib/stats";
import type { ServiceOut } from "../api/types";

const SERVICES: ServiceOut[] = [
  { host: "10.0.0.1", port: 22, protocol: "tcp", service: "ssh", product: "OpenSSH", version: "7.4", cpe: null },
  { host: "10.0.0.1", port: 80, protocol: "tcp", service: "http", product: "nginx", version: "1.22.1", cpe: null },
];

const FINDINGS = [
  finding({ id: 1, port: 22, title: "regreSSHion", severity: "high", cvss: 8.1, software: "OpenSSH", software_version: "7.4", software_source: "service" }),
  finding({ id: 2, port: 22, title: "Username enum", severity: "medium", cvss: 5.3, vuln_id: "CVE-2016-6210", software: "OpenSSH", software_version: "7.4", software_source: "service" }),
  finding({ id: 3, port: null, title: "nginx resolver", severity: "critical", cvss: 9.4, vuln_id: "CVE-2021-23017", software: "nginx", software_version: "1.22.1", software_source: "package" }),
  finding({ id: 4, port: 80, title: "nginx range", severity: "low", cvss: 3.1, vuln_id: "CVE-1", software: "nginx", software_version: "1.22.1", software_source: "service" }),
  finding({ id: 5, port: null, module: "config_audit", title: "PermitRootLogin yes", severity: "medium", cvss: null, vuln_id: "CFG-1" }),
  finding({ id: 6, port: 22, title: "Ложное", severity: "critical", vuln_id: "CVE-2", software: "OpenSSH", software_version: "7.4", false_positive: { reason: null, marked_by: "op", marked_at: "2026-10-29T00:00:00" } }),
];

describe("bySoftware", () => {
  it("группирует по продукту и версии, объединяя порт и пакет", () => {
    const rows = bySoftware(FINDINGS, SERVICES);
    expect(rows.map((r) => [r.name, r.version, r.total])).toEqual([
      ["nginx", "1.22.1", 2],
      ["OpenSSH", "7.4", 2], // ложное срабатывание в группе, но не в счёте
      ["Аудит конфигураций", null, 1],
    ]);
    expect(rows[0].ports).toEqual(["80/tcp"]);
    expect(rows[0].fromPackage).toBe(true);
    expect(rows[0].maxSeverity).toBe("critical");
    expect(rows[1].findings).toHaveLength(3);
    expect(rows[1].maxCvss).toBe(8.1);
    expect(rows[2].known).toBe(false);
  });

  it("без поля software берёт ПО из сервиса на порту", () => {
    const rows = bySoftware([finding({ port: 22 }), finding({ port: 8443, vuln_id: "CVE-9" })], SERVICES);
    expect(rows.map((r) => r.name).sort()).toEqual(["OpenSSH", "Сервис на порту 8443"]);
  });
});

it("по клику на ПО раскрывает список его уязвимостей", async () => {
  const onOpen = vi.fn();
  render(<SoftwareTable findings={FINDINGS} services={SERVICES} onOpen={onOpen} />);
  expect(screen.queryByText("regreSSHion")).not.toBeInTheDocument();
  await userEvent.click(screen.getByText("OpenSSH"));
  expect(screen.getByText("regreSSHion")).toBeInTheDocument();
  expect(screen.getByText("Username enum")).toBeInTheDocument();
  expect(screen.queryByText("nginx resolver")).not.toBeInTheDocument();
  await userEvent.click(screen.getByText("regreSSHion"));
  expect(onOpen).toHaveBeenCalledWith(expect.objectContaining({ id: 1 }));
  // свернуть обратно
  await userEvent.click(screen.getByRole("button", { name: "Свернуть уязвимости OpenSSH" }));
  expect(screen.queryByText("regreSSHion")).not.toBeInTheDocument();
  // раскрыть все
  await userEvent.click(screen.getByRole("button", { name: "Раскрыть все" }));
  const table = screen.getAllByRole("table")[0];
  expect(within(table).getByText("nginx resolver")).toBeInTheDocument();
  expect(within(table).getByText("PermitRootLogin yes")).toBeInTheDocument();
});
