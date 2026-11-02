import { errorText } from "../api/client";
import { runName, runTitle, scheduleWhen } from "./labels";
import { parseDate, plural } from "./format";
import { bduUrl, cveUrl } from "./refs";
import { compactAddresses, inAllowlist, isIpOrCidr, mergeTargets, parseRange, parseTargets, specSize } from "./targets";

describe("targets", () => {
  it("принимает IP и CIDR, отклоняет имена", () => {
    expect(isIpOrCidr("10.0.0.1")).toBe(true);
    expect(isIpOrCidr("10.0.0.0/24")).toBe(true);
    expect(isIpOrCidr("2001:db8::/64")).toBe(true);
    expect(isIpOrCidr("10.0.0.0/33")).toBe(false);
    expect(isIpOrCidr("256.0.0.1")).toBe(false);
    expect(isIpOrCidr("example.com")).toBe(false);
  });
  it("разбирает список с дублями и разделителями", () => {
    expect(parseTargets("10.0.0.1, 10.0.0.1\n10.0.1.0/24; host.local")).toEqual({
      targets: ["10.0.0.1", "10.0.1.0/24"],
      invalid: ["host.local"],
    });
  });
});

describe("диапазоны целей", () => {
  it("полная и краткая форма, пробелы вокруг дефиса", () => {
    expect(parseTargets("10.0.0.1-10.0.0.50\n10.0.1.1 - 20, 10.0.2.9-3").targets).toEqual(["10.0.0.1-10.0.0.50", "10.0.1.1-20"]);
    expect(parseTargets("10.0.2.9-3").invalid).toEqual(["10.0.2.9-3"]); // конец меньше начала
    expect(parseRange("10.0.0.1-300")).toBeNull();
    expect(parseRange("10.0.0.1-2001:db8::1")).toBeNull();
    expect(specSize("10.0.0.1-50")).toBe(50);
    expect(specSize("10.0.0.250-10.0.1.5")).toBe(12);
    expect(specSize("10.0.0.0/24")).toBe(256);
    expect(specSize("2001:db8::1-2001:db8::10")).toBe(16);
  });
  it("проверка адреса по allowlist", () => {
    expect(inAllowlist("10.0.0.7", ["10.0.0.0/24"])).toBe(true);
    expect(inAllowlist("10.0.1.7", ["10.0.0.0/24", "10.0.1.6/32"])).toBe(false);
    expect(inAllowlist("10.0.1.6", ["10.0.0.0/24", "10.0.1.6/32"])).toBe(true);
    expect(inAllowlist("2001:db8::5", ["2001:db8::/64"])).toBe(true);
    expect(inAllowlist("2001:db9::5", ["2001:db8::/64"])).toBe(false);
  });
  it("подряд идущие адреса сворачиваются в диапазон, повторы не добавляются", () => {
    expect(compactAddresses(["10.0.0.3", "10.0.0.1", "10.0.0.2", "10.0.0.9", "10.0.0.10", "10.0.0.255", "10.0.1.0", "10.0.1.1"])).toEqual([
      "10.0.0.1-10.0.0.3",
      "10.0.0.9",
      "10.0.0.10",
      "10.0.0.255-10.0.1.1",
    ]);
    expect(mergeTargets("10.0.0.5\n10.0.1.0/24", ["10.0.1.0/24", "10.0.0.6"])).toBe("10.0.0.5\n10.0.1.0/24\n10.0.0.6");
  });
});

describe("format", () => {
  it("считает naive-дату из API временем UTC", () => {
    expect(parseDate("2026-10-28T09:00:00")?.toISOString()).toBe("2026-10-28T09:00:00.000Z");
    expect(parseDate("2026-10-28T09:00:00+03:00")?.toISOString()).toBe("2026-10-28T06:00:00.000Z");
    expect(parseDate(null)).toBeNull();
  });
  it("склоняет числительные", () => {
    expect([1, 2, 5, 11, 21, 104].map((n) => plural(n, ["хост", "хоста", "хостов"]))).toEqual([
      "хост",
      "хоста",
      "хостов",
      "хостов",
      "хост",
      "хоста",
    ]);
  });
});

describe("refs", () => {
  it("строит ссылки на БДУ и NVD", () => {
    expect(bduUrl("BDU:2021-05969")).toBe("https://bdu.fstec.ru/vul/2021-05969");
    expect(bduUrl("BDU:[номер]")).toBeNull();
    expect(cveUrl("cve-2021-44228")).toBe("https://nvd.nist.gov/vuln/detail/CVE-2021-44228");
  });
});

describe("errorText", () => {
  it("разбирает форматы detail из FastAPI", () => {
    expect(errorText("boom", "x")).toBe("boom");
    expect(errorText([{ msg: "a" }, { msg: "b" }], "x")).toBe("a; b");
    expect(errorText({ message: "no targets" }, "x")).toBe("no targets");
    expect(errorText(undefined, "x")).toBe("x");
  });
});

describe("имя прогона и расписание", () => {
  it("строит имя по опциям так же, как бэкенд", () => {
    expect(runTitle(["discovery", "vuln"], ["10.0.0.0/24"])).toBe("Обнаружение + Nuclei · 10.0.0.0/24");
    expect(runTitle(["vuln", "auth_inventory", "config_audit"], ["10.0.0.5", "10.0.0.6", "10.0.0.7", "10.0.0.8"])).toBe(
      "Nuclei + учётная запись + конфигурации · 10.0.0.5, 10.0.0.6 и ещё 2",
    );
    expect(runTitle(["auth_inventory"], ["10.0.0.5"])).toBe("По учётной записи · 10.0.0.5");
    expect(runTitle(["cred_audit"])).toBe("Аудит паролей");
    expect(runTitle([])).toBe("Прогон");
  });
  it("старый прогон без имени подписывается по модулям", () => {
    expect(runName({ name: "", modules: ["discovery"], targets: [] })).toBe("Инвентаризация");
    expect(runName({ name: "Ночной DMZ", modules: ["discovery"], targets: [] })).toBe("Ночной DMZ");
  });
  it("описывает периодичность", () => {
    expect(scheduleWhen({ kind: "weekly", time_of_day: "22:00", weekdays: [0, 4], month_day: null })).toBe("Пн, Пт в 22:00");
    expect(scheduleWhen({ kind: "monthly", time_of_day: "01:00", weekdays: [], month_day: 15 })).toBe("15-го числа в 01:00");
    expect(scheduleWhen({ kind: "daily", time_of_day: "03:00", weekdays: [], month_day: null })).toBe("Каждый день в 03:00");
  });
});
