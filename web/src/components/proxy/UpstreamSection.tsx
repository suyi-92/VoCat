import { DeleteRegular, DesktopRegular, EditRegular, GlobeRegular, PauseRegular, PlayRegular } from "@fluentui/react-icons";
import type { UpstreamProxy } from "../../types";
import { Button, Tag } from "../ui";
import type { LoadError, UpstreamRow } from "./shared";
import { useI18n } from "../../lib/i18n";

export interface UpstreamSectionProps {
  rows: UpstreamRow[];
  loading: boolean;
  error: LoadError | null;
  onRetry: () => void;
  onEdit: (proxy: UpstreamProxy) => void;
  onDelete: (proxy: UpstreamProxy) => void;
  onOpenBindings: (proxy: UpstreamProxy) => void;
  onToggle: (proxy: UpstreamProxy) => void;
  toggleBusyId?: string;
}

export function UpstreamSection({ rows, loading, error, onRetry, onEdit, onDelete, onOpenBindings, onToggle, toggleBusyId }: UpstreamSectionProps) {
  const { t } = useI18n();
  return (
    <div className="ui-card overflow-hidden">
      {error ? (
        <div className="flex items-center justify-between gap-3 border-b border-red-200 bg-red-50 p-3 text-sm text-red-600 dark:border-red-500/20 dark:bg-red-500/10 dark:text-red-300">
          <span className="min-w-0 truncate">
            {t("加载上游代理失败")}：{error.message}
            {error.status ? `（${error.status}）` : ""}
          </span>
          <button type="button" className="shrink-0 font-medium underline underline-offset-2" onClick={onRetry}>
            {t("重试")}
          </button>
        </div>
      ) : null}
      <div className="overflow-x-auto">
        <table className="w-full min-w-[1180px] table-fixed text-left text-sm">
          <thead className="border-b border-gray-100 bg-gray-50/70 text-xs uppercase tracking-wide text-gray-500 dark:border-white/10 dark:bg-white/[0.025]">
            <tr>
              <th className="w-[230px] px-4 py-3">{t("名称")}</th>
              <th className="w-[140px] px-4 py-3">{t("协议")}</th>
              <th className="w-[190px] px-4 py-3">{t("地址")}</th>
              <th className="w-[100px] px-4 py-3">{t("状态")}</th>
              <th className="w-[130px] px-4 py-3">{t("SIM / Profile 绑定")}</th>
              <th className="w-[130px] px-4 py-3">{t("国家规则")}</th>
              <th className="px-4 py-3 text-right">{t("操作")}</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100 dark:divide-white/10">
            {rows.map((row) => (
              <tr key={row.id} className="hover:bg-sky-50/40 dark:hover:bg-sky-500/[0.04]">
                <td className="break-words px-4 py-3 align-top font-semibold">{row.name || row.id}</td>
                <td className="px-4 py-3 align-top">
                  <div className="flex flex-col items-start gap-1">
                    <Tag type={row.type === "vless" ? "primary" : "info"}>{row.type === "vless" ? "VLESS Reality" : "SOCKS5"}</Tag>
                    {row.type === "vless" && !row.udp ? <Tag type="warning">{t("UDP 已关闭")}</Tag> : null}
                  </div>
                </td>
                <td className="break-all px-4 py-3 align-top font-mono text-xs">{row.addr}</td>
                <td className="px-4 py-3 align-top"><Tag type={row.enabled ? "success" : "info"}>{row.enabled ? t("已启用") : t("已禁用")}</Tag></td>
                <td className="px-4 py-3 align-top">
                  {row.bindingCount}
                </td>
                <td className="px-4 py-3 align-top">
                  {row.countryNames.length ? (
                    <div className="flex max-w-sm flex-wrap gap-1">
                      {row.countryNames.map((countryName) => <Tag key={countryName} type="primary">{countryName}</Tag>)}
                    </div>
                  ) : <span className="text-gray-400">—</span>}
                </td>
                <td className="px-4 py-3 align-top">
                  <div className="flex flex-wrap justify-end gap-2">
                    <Button
                      size="small"
                      variant={row.enabled ? "warning" : "success"}
                      plain
                      icon={row.enabled ? <PauseRegular /> : <PlayRegular />}
                      loading={toggleBusyId === row.id}
                      onClick={() => onToggle(row)}
                    >{row.enabled ? t("禁用") : t("启用")}</Button>
                    <Button
                      size="small"
                      icon={<DesktopRegular />}
                      disabled={row.type === "vless" && !row.udp}
                      title={row.type === "vless" && !row.udp ? t("VoWiFi 依赖 UDP；请先把 Clash 配置中的 udp 改为 true") : undefined}
                      onClick={() => onOpenBindings(row)}
                    >{t("SIM / Profile 绑定")}</Button>
                    <Button size="small" icon={<EditRegular />} onClick={() => onEdit(row)}>{t("编辑")}</Button>
                    <Button size="small" variant="danger" plain icon={<DeleteRegular />} onClick={() => onDelete(row)}>{t("删除")}</Button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {!loading && !rows.length ? (
        <div className="flex flex-col items-center justify-center px-6 py-16 text-center text-gray-400">
          <GlobeRegular className="mb-3 text-4xl" />
          <div className="text-sm">{t("暂无上游代理")}</div>
          <div className="mt-1 text-xs">{t("新增 SOCKS5，或粘贴 Clash VLESS Reality 配置；再配置国家规则或 ICCID 绑定，未匹配的卡默认直连。")}</div>
        </div>
      ) : null}
      {loading ? <div className="px-6 py-16 text-center text-sm text-gray-400">{t("加载中...")}</div> : null}
    </div>
  );
}
