import { errorText } from "../api/client";
import { parseDate, plural } from "./format";
import { bduUrl, cveUrl } from "./refs";
import { isIpOrCidr, parseTargets } from "./targets";

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
