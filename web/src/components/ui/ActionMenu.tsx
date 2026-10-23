import { useEffect, useRef, useState, type ReactNode } from "react";
import Icon from "./Icon";

// Keep actions in their row's semantic tree while the native popover top layer
// prevents a scrollable table from clipping the menu.
export default function ActionMenu({ label, children }: { label: string; children: ReactNode }) {
  const detailsRef = useRef<HTMLDetailsElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);
  const [open, setOpen] = useState(false);
  useEffect(() => {
    if (!open) return;
    const close = (event: Event) => {
      if (event.target instanceof Node && menuRef.current?.contains(event.target)) return;
      if (detailsRef.current) detailsRef.current.open = false;
    };
    window.addEventListener("resize", close);
    window.addEventListener("scroll", close, true);
    return () => {
      window.removeEventListener("resize", close);
      window.removeEventListener("scroll", close, true);
    };
  }, [open]);
  return (
    <details
      className="asset-more"
      ref={detailsRef}
      onToggle={(event) => {
        if (event.target !== event.currentTarget) return;
        setOpen(event.currentTarget.open);
        const menu = menuRef.current;
        if (!menu) return;
        if (!event.currentTarget.open) {
          menu.hidePopover?.();
          return;
        }
        menu.showPopover?.();
        const rect = event.currentTarget.querySelector("summary")!.getBoundingClientRect();
        const bounds = menu.getBoundingClientRect();
        menu.style.left = `${Math.max(8, Math.min(window.innerWidth - bounds.width - 8, rect.right - bounds.width))}px`;
        menu.style.top = `${Math.max(8, Math.min(window.innerHeight - bounds.height - 8, rect.bottom + 6))}px`;
      }}
    >
      <summary
        className="button-text asset-more-trigger"
        role="button"
        aria-label={label}
        aria-haspopup="true"
      >
        {label}
        <Icon name="chevron" size={12} />
      </summary>
      <div
        className="asset-more-menu"
        ref={menuRef}
        popover="auto"
        onToggle={(event) => {
          if (
            event.target === event.currentTarget &&
            !event.currentTarget.matches(":popover-open") &&
            detailsRef.current
          )
            detailsRef.current.open = false;
        }}
        onKeyDown={(event) => {
          if (!["ArrowDown", "ArrowUp", "Home", "End"].includes(event.key)) return;
          const items = [
            ...event.currentTarget.querySelectorAll<HTMLButtonElement>("button:not(:disabled)"),
          ];
          const current = items.indexOf(document.activeElement as HTMLButtonElement);
          if (!items.length) return;
          event.preventDefault();
          items[
            event.key === "Home"
              ? 0
              : event.key === "End"
                ? items.length - 1
                : (current + (event.key === "ArrowDown" ? 1 : -1) + items.length) % items.length
          ].focus();
        }}
      >
        {children}
      </div>
    </details>
  );
}
