/** Варианты табличной выгрузки для кнопок ExportButtons. */
export interface ExportOption {
  id: string;
  label: string;
  /** Подсказка: что будет в файле. */
  title?: string;
}

export const FINDINGS_EXPORTS: ExportOption[] = [
  { id: "xlsx", label: "Excel", title: "Все находки по текущим фильтрам, с рекомендациями и ссылками на устранение" },
  { id: "csv", label: "CSV", title: "То же в CSV (UTF-8, разделитель «;»)" },
];

export const FIX_EXPORTS: ExportOption[] = [
  { id: "xlsx", label: "Excel", title: "Действия с командами, лист «По хостам» и сведения о выгрузке" },
  { id: "csv", label: "CSV", title: "Строка на действие: команды, проверка, хосты, CVE/БДУ, ссылки" },
  { id: "csv-hosts", label: "CSV по хостам", title: "Строка на действие × хост — удобно раздать администраторам" },
];
