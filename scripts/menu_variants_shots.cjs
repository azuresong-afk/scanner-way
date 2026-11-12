const { chromium } = require("playwright");
const OUT = process.argv[2];
const BASE = "http://localhost:5179";
const ALL = ["manage_users","manage_engagements","manage_nodes","manage_allowlist","view_engagements","run_scan","view_report","view_audit","host_credentials","cred_audit","triage_findings"];
const d = (h) => new Date(Date.now() - h*3600e3).toISOString().slice(0,19);
const run = (id, name, status, h, durMin, profile="normal") => ({ id, engagement_id:1, modules:["discovery","vuln"], rate_profile:profile, credential_ids:[], cred_set_ids:[], name, targets:["10.0.0.0/24"], schedule_id:null, status, started_by:1, started_at:d(h), finished_at: status==="running"?null:d(h-durMin/60), created_at:d(h), progress: status==="running"?{stage:"vuln",stage_index:2,stages:3,hosts_done:14,hosts_total:23,percent:61}:null });
const runs = [
  run(48,"Полный: 10.0.0.0/24 · Nuclei + по учётной записи","running",0.4,0),
  run(47,"Ежедневная проверка ДМЗ","done",20,38),
  run(46,"Сетевой поиск: 10.0.1.0/24","done",28,12,"gentle"),
  run(45,"Проверка СУБД: биллинг","partial",44,21),
  run(44,"Ежедневная проверка ДМЗ","done",68,41),
  run(43,"Windows-домен: WinRM","stopped",80,9),
  run(42,"Ежедневная проверка ДМЗ","done",92,40),
  run(41,"Аудит конфигураций по ФСТЭК №117","done",120,55),
  run(40,"Полный: 10.0.0.0/24 · Nuclei","done",170,64,"aggressive"),
];
const sched = (id,title,kind,t,wd,en,next,last) => ({ id, engagement_id:1, name:title, title, targets:["10.0.0.0/24"], modules:["discovery","vuln"], rate_profile:"normal", credential_ids:[], cred_set_ids:[], kind, time_of_day:t, weekdays:wd, month_day:kind==="monthly"?1:null, run_at:null, timezone:"Europe/Moscow", enabled:en, next_run_at:next, last_run_at:last, last_result:"queued", last_run_id:47, owner_id:1, node_id:null });
const schedules = [
  sched(1,"Ежедневная проверка ДМЗ","daily","03:00",[],true,"2026-11-13T00:00:00","2026-11-12T00:00:00"),
  sched(2,"Аудит конфигураций по ФСТЭК №117","weekly","02:00",[6],true,"2026-11-14T23:00:00","2026-11-07T23:00:00"),
  sched(3,"Проверка СУБД: биллинг","monthly","04:00",[],true,"2026-11-30T01:00:00","2026-10-31T01:00:00"),
  sched(4,"Сетевой поиск по всем подсетям","weekly","22:00",[2,4],false,null,"2026-10-29T19:00:00"),
];
const comp = (id,title,status,summary) => ({ id, title, status, summary, hint:null, items:[], details:{} });
const health = { status:"ok", status_title:"Всё работает", checked_at:d(0.05), components:[
  comp("db","База данных","ok","PostgreSQL 16, 2,1 ГБ, отвечает за 3 мс"),
  comp("runs","Прогоны","ok","Идёт 1 прогон, очередь пуста"),
  comp("feeds","Справочники","ok","БДУ, NVD, бюллетени обновлены сегодня"),
  comp("nodes","Узлы-сканеры","ok","2 узла на связи"),
  comp("notify","Уведомления","ok","Каналы доставляют без ошибок"),
  comp("disk","Диск","ok","Свободно 412 ГБ из 500 ГБ"),
]};
const routes = {
  "GET /me": { id:1, username:"ivanov", display_name:"Иванов", is_active:true, roles:["operator","admin"], permissions:ALL },
  "GET /engagements": [{ id:1, name:"Периметр", client:"ООО Тест", contract_ref:"Д-2026/114", created_by:1, created_at:d(500) }],
  "GET /system/health": health,
  "GET /engagements/1/schedules": schedules,
};
(async () => {
  const browser = await chromium.launch();
  const variants = (process.argv[3]||"now,v1,v2,v3,v4").split(",");
  const pages = (process.argv[4]||"runs:/runs,sched:/schedules").split(",");
  for (const v of variants) for (const theme of ["light","dark"]) for (const pg of pages) {
    const [name, path] = pg.split(":");
    const ctx = await browser.newContext({ viewport: process.env.MEASURE ? { width:1366, height:768 } : { width:1440, height:900 }, deviceScaleFactor: process.env.MEASURE ? 1 : 2, locale:"ru-RU", timezoneId:"Europe/Moscow" });
    await ctx.addInitScript(([v,theme]) => { sessionStorage.setItem("scanner.token","t"); localStorage.setItem("scanner.theme",theme); localStorage.setItem("scanner.menu",v); localStorage.setItem("scanner.engagement","1"); }, [v,theme]);
    const page = await ctx.newPage();
    page.on("pageerror", e => console.error("pageerror", e.message));
    await page.route((url) => url.pathname.startsWith("/api/"), (r) => {
      const u = new URL(r.request().url()); const p = u.pathname.replace(/^\/api/,""); const key = `${r.request().method()} ${p}`;
      let body = routes[key];
      if (body === undefined && /\/engagements\/1\/runs$/.test(p)) {
        const st = u.searchParams.getAll("status");
        const items = st.length ? runs.filter(x=>st.includes(x.status)) : runs;
        return r.fulfill({ status:200, contentType:"application/json", headers:{"X-Total-Count":String(items.length)}, body: JSON.stringify(items.slice(0, Number(u.searchParams.get("limit")||25))) });
      }
      if (body === undefined) { console.error("unmocked", key); return r.fulfill({ status:404, contentType:"application/json", body:'{"detail":"not mocked"}' }); }
      r.fulfill({ status:200, contentType:"application/json", body: JSON.stringify(body) });
    });
    await page.goto(BASE + path);
    await page.waitForTimeout(900);
    if (process.env.MEASURE) {
      const m = await page.evaluate(() => { const s = document.querySelector(".sidebar"); const foot = s.querySelector(".sidebar-foot"); const kids = [...s.children].filter((c) => c !== foot); const last = kids[kids.length - 1].getBoundingClientRect(); return { need: Math.round(last.bottom + foot.getBoundingClientRect().height + parseFloat(getComputedStyle(s).paddingBottom)), width: Math.round(s.getBoundingClientRect().width), topbar: Math.round(document.querySelector(".topbar").getBoundingClientRect().height), brand: Math.round(s.querySelector(".brand").getBoundingClientRect().height), link: Math.round(s.querySelector(".nav-link").getBoundingClientRect().height) }; });
      if (theme === "light") console.log(v, name, JSON.stringify(m));
    } else await page.screenshot({ path: `${OUT}/${v}-${name}-${theme}.png` });
    await ctx.close();
  }
  await browser.close();
})();
