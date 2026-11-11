import { useRef } from "react";
import { Copy, Download } from "lucide-react";
import type { MfaSetupOut } from "../api/types";
import { useCopy } from "../lib/clipboard";
import { saveBlob } from "../lib/download";

/** Поле кода из приложения-аутентификатора (6 цифр) или кода восстановления. */
export function CodeField({
  value,
  onChange,
  label = "Код из приложения",
  allowRecovery = false,
  autoFocus = true,
}: {
  value: string;
  onChange: (v: string) => void;
  label?: string;
  allowRecovery?: boolean;
  autoFocus?: boolean;
}) {
  return (
    <label className="field">
      <span>{label}</span>
      <input
        className="input mono"
        style={{ fontSize: 18, letterSpacing: "0.2em" }}
        inputMode={allowRecovery ? "text" : "numeric"}
        autoComplete="one-time-code"
        maxLength={allowRecovery ? 16 : 7}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        autoFocus={autoFocus}
        required
      />
      {allowRecovery && <small>6 цифр из приложения или код восстановления вида xxxxx-xxxxx</small>}
    </label>
  );
}

/** QR-код и секрет для приложения-аутентификатора. */
export function MfaSetupBox({ setup }: { setup: MfaSetupOut }) {
  const grouped = setup.secret.replace(/(.{4})/g, "$1 ").trim();
  return (
    <div className="stack" style={{ gap: 13 }}>
      <ol className="muted" style={{ margin: 0, paddingLeft: 18, display: "flex", flexDirection: "column", gap: 4, fontSize: 13 }}>
        <li>Установите на телефон приложение-аутентификатор: Яндекс Ключ, Google Authenticator, FreeOTP или аналог.</li>
        <li>Отсканируйте QR-код или введите ключ вручную.</li>
        <li>Введите 6-значный код, который покажет приложение.</li>
      </ol>
      {setup.qr_svg && (
        <img
          src={`data:image/svg+xml;utf8,${encodeURIComponent(setup.qr_svg)}`}
          alt="QR-код для приложения-аутентификатора"
          width={168}
          height={168}
          style={{ alignSelf: "center", borderRadius: 8, background: "#fff", padding: 4 }}
        />
      )}
      <div className="field">
        <span>Ключ для ручного ввода</span>
        <code className="mono" style={{ fontSize: 14, wordBreak: "break-all", userSelect: "all" }} aria-label="Ключ">
          {grouped}
        </code>
      </div>
    </div>
  );
}

/** Одноразовые коды восстановления: показываются один раз. */
export function RecoveryCodesBox({ codes, username }: { codes: string[]; username: string }) {
  const [copyState, copy] = useCopy();
  const list = useRef<HTMLUListElement>(null);
  const text = codes.join("\n");
  return (
    <div className="stack" style={{ gap: 13 }}>
      <div className="alert alert-warn" role="note">
        Сохраните коды восстановления в надёжном месте. Каждый код срабатывает один раз и заменяет код из приложения, если телефон потерян. Больше они показаны не будут.
      </div>
      <ul
        ref={list}
        aria-label="Коды восстановления"
        className="mono"
        style={{ listStyle: "none", margin: 0, padding: 0, display: "grid", gridTemplateColumns: "1fr 1fr", gap: "6px 21px", fontSize: 14 }}
      >
        {codes.map((c) => (
          <li key={c}>{c}</li>
        ))}
      </ul>
      <div className="inline" style={{ gap: 8 }}>
        <button type="button" className="btn btn-sm" onClick={() => void copy(text, list.current)}>
          <Copy size={14} /> {copyState === "ok" ? "Скопировано" : "Скопировать"}
        </button>
        {copyState === "fail" && (
          <span className="faint" role="status">
            Не удалось скопировать — коды выделены, нажмите Ctrl+C
          </span>
        )}
        <button type="button" className="btn btn-sm" onClick={() => saveBlob(new Blob([text + "\n"], { type: "text/plain" }), `scanner-recovery-${username}.txt`)}>
          <Download size={14} /> Скачать .txt
        </button>
      </div>
    </div>
  );
}
