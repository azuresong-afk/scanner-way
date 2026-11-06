/** Код похож на допустимый: 6 цифр или код восстановления из 10 символов. */
export function codeLooksValid(code: string, allowRecovery = false): boolean {
  const c = code.replace(/\s/g, "");
  if (/^\d{6}$/.test(c)) return true;
  return allowRecovery && c.replace(/-/g, "").length === 10;
}
