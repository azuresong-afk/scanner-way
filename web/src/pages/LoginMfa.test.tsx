import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { App } from "../App";
import { getToken, setToken } from "../api/client";
import { AuthProvider } from "../auth/AuthContext";
import { ThemeProvider } from "../theme/ThemeContext";
import { ADMIN, OPERATOR, me, mockApi } from "../test/fixtures";

function renderApp(path = "/") {
  return render(
    <ThemeProvider>
      <MemoryRouter initialEntries={[path]} future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
        <AuthProvider>
          <App />
        </AuthProvider>
      </MemoryRouter>
    </ThemeProvider>,
  );
}

afterEach(() => {
  setToken(null);
  vi.unstubAllGlobals();
  localStorage.clear();
});

async function typePassword() {
  await userEvent.type(await screen.findByLabelText("Имя пользователя"), "ivanov");
  await userEvent.type(screen.getByLabelText("Пароль"), "correct-horse-battery");
  await userEvent.click(screen.getByRole("button", { name: /Войти/ }));
}

it("подсказывает вход учётной записью домена, если включён LDAP", async () => {
  mockApi({ "GET /auth/config": { ldap: true, mfa: "off" } });
  renderApp("/login");
  expect(await screen.findByText("Войдите учётной записью домена или выданной администратором.")).toBeInTheDocument();
});

it("после пароля спрашивает код 2FA и только потом входит", async () => {
  const api = mockApi({
    "GET /auth/config": { ldap: false, mfa: "optional" },
    "POST /auth/token": { token_type: "bearer", mfa_required: true, mfa_enroll: false, mfa_token: "pending" },
    "POST /auth/mfa": (init: RequestInit | undefined) => {
      const b = JSON.parse(String(init?.body));
      if (b.code !== "123456") return new Response(JSON.stringify({ detail: "invalid code" }), { status: 400 });
      return { access_token: "tok-2fa", token_type: "bearer", expires_in: 3600 };
    },
    "GET /me": me(["auditor"], ["view_engagements", "view_report", "view_audit"]),
    "GET /engagements": [],
  });
  renderApp("/");
  await typePassword();
  expect(await screen.findByRole("heading", { name: "Подтверждение входа" })).toBeInTheDocument();
  expect(getToken()).toBeNull();
  const code = screen.getByLabelText(/Код из приложения/);
  await userEvent.type(code, "000000");
  await userEvent.click(screen.getByRole("button", { name: "Подтвердить" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("Неверный код");
  await userEvent.clear(code);
  await userEvent.type(code, "123456");
  await userEvent.click(screen.getByRole("button", { name: "Подтвердить" }));
  await screen.findByRole("navigation", { name: "Основное меню" });
  expect(getToken()).toBe("tok-2fa");
  const sent = api.calls.find((c) => c.path === "/auth/mfa" && JSON.parse(String(c.init?.body)).code === "123456");
  expect(JSON.parse(String(sent?.init?.body)).mfa_token).toBe("pending");
});

it("обязательная 2FA: настройка при входе с QR-кодом и кодами восстановления", async () => {
  mockApi({
    "GET /auth/config": { ldap: false, mfa: "required" },
    "POST /auth/token": { token_type: "bearer", mfa_required: true, mfa_enroll: true, mfa_token: "pending" },
    "POST /auth/mfa/enroll": { secret: "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP", otpauth_uri: "otpauth://totp/Scanner:ivanov?secret=X", qr_svg: "<svg xmlns='http://www.w3.org/2000/svg'></svg>" },
    "POST /auth/mfa/enroll/confirm": { access_token: "tok-new", token_type: "bearer", expires_in: 3600, recovery_codes: ["aaaaa-bbbbb", "ccccc-ddddd"] },
    "GET /me": me(["operator"], OPERATOR),
    "GET /engagements": [],
  });
  renderApp("/");
  await typePassword();
  expect(await screen.findByRole("heading", { name: "Настройка двухфакторного входа" })).toBeInTheDocument();
  expect(screen.getByAltText("QR-код для приложения-аутентификатора")).toBeInTheDocument();
  expect(screen.getByLabelText("Ключ")).toHaveTextContent("JBSW Y3DP");
  await userEvent.type(screen.getByLabelText(/Код из приложения/), "654321");
  await userEvent.click(screen.getByRole("button", { name: "Подтвердить" }));
  expect(await screen.findByText("aaaaa-bbbbb")).toBeInTheDocument();
  // до подтверждения, что коды сохранены, вход не завершается
  expect(getToken()).toBeNull();
  await userEvent.click(screen.getByRole("button", { name: /Я сохранил коды/ }));
  await screen.findByRole("navigation", { name: "Основное меню" });
  expect(getToken()).toBe("tok-new");
});

it("пользователь из домена: роли и пароль не редактируются, 2FA можно сбросить", async () => {
  setToken("t");
  const api = mockApi({
    "GET /me": me(["admin"], ADMIN),
    "GET /engagements": [],
    "GET /users": [
      { id: 1, username: "tester", display_name: "Тест", is_active: true, roles: ["admin"], auth_source: "local", mfa_enabled: false },
      { id: 7, username: "ivanov", display_name: "Иванов И. И.", is_active: true, roles: ["operator"], auth_source: "ldap", mfa_enabled: true },
    ],
    "DELETE /users/7/mfa": { id: 7, username: "ivanov", display_name: "Иванов И. И.", is_active: true, roles: ["operator"], auth_source: "ldap", mfa_enabled: false },
  });
  renderApp("/users");
  expect(await screen.findByText("Домен")).toBeInTheDocument();
  expect(screen.getByTitle("Двухфакторный вход включён")).toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: "Изменить ivanov" }));
  expect(screen.getByText(/Учётная запись домена \(AD\)/)).toBeInTheDocument();
  expect(screen.queryByLabelText("Новый пароль")).toBeNull();
  await userEvent.click(screen.getByRole("button", { name: "Сбросить 2FA" }));
  await userEvent.click(screen.getByRole("button", { name: "Да, сбросить" }));
  await screen.findByRole("button", { name: "Сохранить" });
  expect(api.calls.some((c) => c.method === "DELETE" && c.path === "/users/7/mfa")).toBe(true);
  expect(screen.queryByRole("button", { name: "Сбросить 2FA" })).toBeNull();
});

it("профиль: включение 2FA показывает QR и коды восстановления", async () => {
  setToken("t");
  let enabled = false;
  mockApi({
    "GET /me": me(["operator"], OPERATOR),
    "GET /engagements": [],
    "GET /me/mfa": () => ({ mode: "optional", enabled, required: false, recovery_codes_left: enabled ? 10 : 0 }),
    "POST /me/mfa/setup": { secret: "JBSWY3DPEHPK3PXP", otpauth_uri: "otpauth://totp/x", qr_svg: null },
    "POST /me/mfa/confirm": () => {
      enabled = true;
      return { recovery_codes: ["zzzzz-yyyyy"] };
    },
  });
  renderApp("/security");
  await userEvent.click(await screen.findByRole("button", { name: "Включить" }));
  expect(await screen.findByLabelText("Ключ")).toHaveTextContent("JBSW Y3DP EHPK 3PXP");
  await userEvent.type(screen.getByLabelText(/Код из приложения/), "111222");
  await userEvent.click(screen.getByRole("button", { name: "Подтвердить и включить" }));
  expect(await screen.findByText("zzzzz-yyyyy")).toBeInTheDocument();
  expect(await screen.findByText("Включён")).toBeInTheDocument();
});
