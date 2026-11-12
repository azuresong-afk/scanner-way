import { describe, expect, it } from "vitest";
import { canExtend, deviceLabel, sessionStep, type TokenClock } from "./session";

const MIN = 60_000;
const clock = (over: Partial<TokenClock> = {}): TokenClock => ({
  issuedAt: 0,
  expiresAt: 60 * MIN,
  sessionEndsAt: null,
  ...over,
});

describe("sessionStep", () => {
  it("работал после выдачи и прошла половина срока — продлить", () => {
    expect(sessionStep(clock(), 31 * MIN, 10 * MIN)).toEqual({ kind: "refresh" });
  });
  it("работал, но половина срока не прошла — ждать", () => {
    expect(sessionStep(clock(), 20 * MIN, 19 * MIN)).toEqual({ kind: "ok" });
  });
  it("бездействие — не продлевать, предупредить за 5 минут", () => {
    expect(sessionStep(clock(), 40 * MIN, 0)).toEqual({ kind: "ok" });
    expect(sessionStep(clock(), 56 * MIN, 0)).toEqual({ kind: "warn", leftMs: 4 * MIN, final: false });
  });
  it("срок вышел — выход", () => {
    expect(sessionStep(clock(), 60 * MIN, 59 * MIN)).toEqual({ kind: "expired" });
  });
  it("упёрлись в предел сеанса — не продлить, предупредить о новом входе", () => {
    const c = clock({ sessionEndsAt: 60 * MIN });
    expect(canExtend(c)).toBe(false);
    expect(sessionStep(c, 50 * MIN, 49 * MIN)).toEqual({ kind: "ok" });
    expect(sessionStep(c, 57 * MIN, 56 * MIN)).toEqual({ kind: "warn", leftMs: 3 * MIN, final: true });
  });
  it("короткий срок токена — предупреждение за четверть срока", () => {
    const c = clock({ expiresAt: 8 * MIN });
    expect(sessionStep(c, 5 * MIN, 0).kind).toBe("ok");
    expect(sessionStep(c, 7 * MIN, 0).kind).toBe("warn");
  });
});

describe("deviceLabel", () => {
  it("браузер и ОС", () => {
    expect(
      deviceLabel("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36"),
    ).toBe("Chrome, Linux");
    expect(deviceLabel("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0")).toBe(
      "Firefox, Windows",
    );
    expect(deviceLabel(null)).toBe("Неизвестное устройство");
    expect(deviceLabel("curl/8.5.0")).toBe("curl/8.5.0");
  });
});
