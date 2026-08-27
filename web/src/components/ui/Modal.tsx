import { useEffect, useId, useRef, type ReactNode } from "react";
import { DismissRegular } from "@fluentui/react-icons";
import { cx } from "../../lib/utils";
import { useI18n } from "../../lib/i18n";

export interface ModalProps {
  open: boolean;
  onClose: () => void;
  title?: ReactNode;
  width?: string;
  children: ReactNode;
  footer?: ReactNode;
  showClose?: boolean;
  closeOnOverlay?: boolean;
  className?: string;
  bodyClassName?: string;
}

// Glassmorphism modal replicating VoHive's `.el-dialog.glass-modal`.
export function Modal({
  open,
  onClose,
  title,
  width = "max-w-lg",
  children,
  footer,
  showClose = true,
  closeOnOverlay = true,
  className,
  bodyClassName,
}: ModalProps) {
  const { t } = useI18n();
  const dialogRef = useRef<HTMLDivElement>(null);
  const titleId = useId();
  useEffect(() => {
    if (!open) return;
    const previousFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const focusableSelector = [
      "button:not([disabled])",
      "[href]",
      "input:not([disabled])",
      "select:not([disabled])",
      "textarea:not([disabled])",
      "[tabindex]:not([tabindex='-1'])",
    ].join(",");
    const frame = window.requestAnimationFrame(() => {
      const dialog = dialogRef.current;
      if (!dialog || dialog.contains(document.activeElement)) return;
      (dialog.querySelector<HTMLElement>("[autofocus]") || dialog.querySelector<HTMLElement>(focusableSelector) || dialog).focus();
    });
    function onKey(event: KeyboardEvent) {
      if (event.key === "Escape") {
        event.preventDefault();
        onClose();
        return;
      }
      if (event.key !== "Tab") return;
      const dialog = dialogRef.current;
      if (!dialog) return;
      const focusable = Array.from(dialog.querySelectorAll<HTMLElement>(focusableSelector))
        .filter((element) => !element.hasAttribute("disabled") && element.getAttribute("aria-hidden") !== "true");
      if (!focusable.length) {
        event.preventDefault();
        dialog.focus();
        return;
      }
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    }
    window.addEventListener("keydown", onKey);
    return () => {
      window.cancelAnimationFrame(frame);
      window.removeEventListener("keydown", onKey);
      previousFocus?.focus();
    };
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-[3000] flex items-center justify-center overflow-y-auto bg-black/50 p-4 backdrop-blur-sm animate-[fade-slide-in_0.2s_ease]"
      onMouseDown={(event) => {
        if (closeOnOverlay && event.target === event.currentTarget) onClose();
      }}
    >
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={title ? titleId : undefined}
        aria-label={title ? undefined : t("对话框")}
        tabIndex={-1}
        className={cx(
          "glass-modal relative flex max-h-[calc(100dvh-2rem)] w-full flex-col rounded-2xl shadow-2xl animate-[fade-slide-in_0.25s_cubic-bezier(0.4,0,0.2,1)]",
          width,
          className,
        )}
      >
        {(title || showClose) && (
          <div className="flex shrink-0 items-center justify-between px-6 pt-5 pb-3">
            <div id={title ? titleId : undefined} className="text-base font-bold text-gray-900 dark:text-white">{title}</div>
            {showClose && (
              <button
                type="button"
                onClick={onClose}
                aria-label={t("关闭")}
                className="rounded-md p-1 text-gray-400 transition-colors hover:bg-black/5 hover:text-gray-600 dark:hover:bg-white/10 dark:hover:text-gray-200"
              >
                <DismissRegular className="text-[18px]" />
              </button>
            )}
          </div>
        )}
        <div className={cx("min-h-0 flex-1 overflow-y-auto px-6 pb-5", !title && "pt-5", bodyClassName)}>{children}</div>
        {footer && <div className="flex shrink-0 items-center justify-end gap-3 px-6 pb-5">{footer}</div>}
      </div>
    </div>
  );
}
