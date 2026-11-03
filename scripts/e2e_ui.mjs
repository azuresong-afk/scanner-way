// Проверка веб-интерфейса в браузере (часть scripts/e2e.sh): вход через форму,
// «Сводка», «Сканирование» (прогоны) → карточка прогона стенда, «Находки» с постраничным
// выводом, «Отчёты». Ошибки JavaScript на странице и ответы API 5xx валят
// проверку. Снимки экрана — в SCANNER_E2E_ARTIFACTS.
//
//   SCANNER_E2E_URL=http://127.0.0.1:28080 SCANNER_E2E_USER=admin \
//   SCANNER_E2E_PASSWORD=… node scripts/e2e_ui.mjs
import { createRequire } from "node:module";
import { mkdirSync } from "node:fs";
import { join } from "node:path";

const require = createRequire(join(process.cwd(), "noop.js"));
const { chromium } = require("playwright");

const URL = process.env.SCANNER_E2E_URL;
const USER = process.env.SCANNER_E2E_USER;
const PASSWORD = process.env.SCANNER_E2E_PASSWORD;
const OUT = process.env.SCANNER_E2E_ARTIFACTS || "e2e-artifacts";
const RUN_NAME = process.env.SCANNER_E2E_RUN_NAME || "e2e: стенд";
const TARGET = process.env.SCANNER_E2E_TARGET || "172.29.250.10";
if (!URL || !USER || !PASSWORD) {
  console.error("нужны SCANNER_E2E_URL, SCANNER_E2E_USER, SCANNER_E2E_PASSWORD");
  process.exit(2);
}
mkdirSync(OUT, { recursive: true });

const problems = [];
const browser = await chromium.launch(process.env.E2E_CHROMIUM ? { executablePath: process.env.E2E_CHROMIUM } : {});
const page = await browser.newPage({ viewport: { width: 1440, height: 900 }, locale: "ru-RU" });
page.on("pageerror", (e) => problems.push(`ошибка JS: ${e.message}`));
page.on("response", (r) => {
  if (r.url().includes("/api/") && r.status() >= 500) problems.push(`API ${r.status()}: ${r.url()}`);
});

async function step(name, fn) {
  try {
    await fn();
    await page.screenshot({ path: join(OUT, `ui-${name}.png`), fullPage: true });
    console.log(`[ui] ok  ${name}`);
  } catch (e) {
    await page.screenshot({ path: join(OUT, `ui-${name}-FAILED.png`), fullPage: true }).catch(() => {});
    console.error(`[ui] FAIL ${name}: ${e.message}`);
    problems.push(`${name}: ${e.message}`);
  }
}

const timeout = 30000;
await step("login", async () => {
  await page.goto(`${URL}/login`);
  await page.getByLabel("Имя пользователя").fill(USER);
  await page.getByLabel("Пароль").fill(PASSWORD);
  await page.getByRole("button", { name: "Войти" }).click();
  await page.waitForURL((u) => !u.pathname.startsWith("/login"), { timeout });
});

await step("runs", async () => {
  // договор основного сценария — первый (id 1 в свежей базе стека e2e)
  await page.evaluate(() => localStorage.setItem("scanner.engagement", "1"));
  await page.goto(`${URL}/runs`);
  await page.getByText(RUN_NAME).first().waitFor({ timeout });
});

await step("run-detail", async () => {
  await page.getByText(RUN_NAME).first().click();
  await page.waitForURL(/\/runs\/\d+$/, { timeout });
  // «Частично» — если Nuclei без шаблонов не отработал (см. test_04)
  await page.getByText(/Завершён|Частично/).first().waitFor({ timeout });
  // находки прогона подгружаются отдельно — дождаться их, а не «Загрузка…»
  await page.getByText("Загрузка…").first().waitFor({ state: "detached", timeout });
  await page.getByText(TARGET).first().waitFor({ timeout });
});

await step("findings", async () => {
  await page.goto(`${URL}/findings`);
  await page.getByText(/Показано \d|Нет записей|В прогоне нет находок|Ничего не найдено|Исправлять нечего/).first().waitFor({ timeout });
});

await step("reports", async () => {
  await page.goto(`${URL}/reports`);
  await page.getByRole("heading", { name: "Отчёты" }).waitFor({ timeout });
  await page.getByText(RUN_NAME).first().waitFor({ timeout });
});

await browser.close();
if (problems.length) {
  console.error(`[ui] проблемы:\n- ${problems.join("\n- ")}`);
  process.exit(1);
}
console.log("[ui] интерфейс проверен");
