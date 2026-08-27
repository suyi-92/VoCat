import { Button, Modal, Textarea } from "../ui";
import { useI18n } from "../../lib/i18n";

const CLASH_EXAMPLE = `- name: 【Dmit-US-LA-PRO】AaITR-Frontier
  type: vless
  server: proxy.example.com
  port: 443
  uuid: 00000000-0000-4000-8000-000000000000
  flow: xtls-rprx-vision
  network: tcp
  tls: true
  client-fingerprint: chrome
  udp: true
  reality-opts:
    public-key: replace-with-x25519-public-key
    short-id: "0123456789abcdef"
  alpn:
    - h2
    - http/1.1
  servername: www.example.com`;

export interface ClashImportDialogProps {
  open: boolean;
  editing: boolean;
  content: string;
  busy: boolean;
  error: string;
  onContentChange: (value: string) => void;
  onClose: () => void;
  onSubmit: () => void;
}

export function ClashImportDialog({
  open,
  editing,
  content,
  busy,
  error,
  onContentChange,
  onClose,
  onSubmit,
}: ClashImportDialogProps) {
  const { t } = useI18n();
  const descriptionId = "clash-proxy-yaml-description";
  const errorId = "clash-proxy-yaml-error";

  return (
    <Modal
      open={open}
      onClose={onClose}
      closeOnOverlay={!busy}
      title={editing ? t("替换 Clash VLESS 代理") : t("导入 Clash VLESS 代理")}
      width="max-w-3xl"
      footer={(
        <>
          <Button onClick={onClose} disabled={busy}>{t("取消")}</Button>
          <Button variant="primary" onClick={onSubmit} loading={busy} disabled={!content.trim()}>
            {editing ? t("识别并更新") : t("识别并添加")}
          </Button>
        </>
      )}
    >
      <div className="space-y-4 pb-2">
        <div className="rounded-xl border border-sky-200 bg-sky-50/80 p-3 text-xs leading-5 text-sky-800 dark:border-sky-500/25 dark:bg-sky-500/10 dark:text-sky-200">
          <div className="font-semibold">{t("粘贴一个标准 Clash 代理条目、代理列表，或包含 proxies: 的完整 YAML。")}</div>
          <div>{t("VoCat 会自动识别 VLESS、Reality、TLS、指纹、ALPN 与 UDP 设置；UUID 只会以脱敏形式返回界面。")}</div>
        </div>

        <div>
          <label htmlFor="clash-proxy-yaml" className="mb-1.5 block text-xs font-bold uppercase tracking-wider text-gray-600 dark:text-gray-300">
            {t("Clash YAML")}
            <span aria-hidden="true" className="ml-1 text-red-500">*</span>
            <span className="sr-only">{t("必填")}</span>
          </label>
          <Textarea
            id="clash-proxy-yaml"
            value={content}
            autoFocus
            required
            spellCheck={false}
            maxLength={65536}
            rows={14}
            placeholder={CLASH_EXAMPLE}
            aria-invalid={!!error}
            aria-describedby={`${descriptionId}${error ? ` ${errorId}` : ""}`}
            className="min-h-[260px] resize-y font-mono text-xs leading-5 sm:min-h-[320px]"
            onChange={(event) => onContentChange(event.target.value)}
            onKeyDown={(event) => {
              if ((event.ctrlKey || event.metaKey) && event.key === "Enter" && content.trim() && !busy) {
                event.preventDefault();
                onSubmit();
              }
            }}
          />
          <div id={descriptionId} className="mt-1.5 flex flex-wrap justify-between gap-2 text-xs text-gray-500 dark:text-gray-400">
            <span>{t("仅支持 VLESS + TCP + TLS Reality；按 Ctrl+Enter 可直接提交。")}</span>
            <span>{content.length.toLocaleString()} / 65,536</span>
          </div>
          {error ? (
            <div id={errorId} role="alert" aria-live="assertive" className="mt-2 rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-xs text-red-700 dark:border-red-500/25 dark:bg-red-500/10 dark:text-red-300">
              {error}
            </div>
          ) : null}
        </div>

        <div className="rounded-lg border border-amber-200 bg-amber-50/70 px-3 py-2 text-xs leading-5 text-amber-800 dark:border-amber-500/25 dark:bg-amber-500/10 dark:text-amber-200">
          {t("注意：VoWiFi 依赖 UDP。配置中的 udp: false 仍可保存，但不能绑定 SIM/Profile 或国家规则。")}
        </div>
      </div>
    </Modal>
  );
}
