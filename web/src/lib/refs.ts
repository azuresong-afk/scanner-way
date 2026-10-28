// Ссылки на карточки в справочниках: БДУ ФСТЭК, NVD, CWE.

export function bduUrl(id: string): string | null {
  const m = /^BDU:(\d{4}-\d{5})$/i.exec(id.trim());
  return m ? `https://bdu.fstec.ru/vul/${m[1]}` : null;
}

export function cveUrl(id: string): string | null {
  return /^CVE-\d{4}-\d{4,}$/i.test(id.trim()) ? `https://nvd.nist.gov/vuln/detail/${id.trim().toUpperCase()}` : null;
}

export function cweUrl(id: string): string | null {
  const m = /^CWE-(\d+)$/i.exec(id.trim());
  return m ? `https://cwe.mitre.org/data/definitions/${m[1]}.html` : null;
}
