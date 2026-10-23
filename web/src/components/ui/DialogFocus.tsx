import { useEffect } from "react";

// Existing feature dialogs share one focus boundary, including nested dialogs.
// No document data or credentials are persisted by this accessibility helper.
export default function DialogFocus() {
  useEffect(() => {
    const selector = '[role="dialog"][aria-modal="true"], dialog[open]';
    const focusable =
      'a[href], button:not(:disabled), input:not(:disabled), select:not(:disabled), textarea:not(:disabled), [tabindex]:not([tabindex="-1"])';
    let current: HTMLElement | null = null;
    const previous = new Map<HTMLElement, HTMLElement | null>();
    const visible = (element: HTMLElement) =>
      element.getClientRects().length > 0 && !element.closest("[hidden], [inert]");
    const candidates = (dialog: HTMLElement) =>
      [...dialog.querySelectorAll<HTMLElement>(focusable)].filter(visible);
    const synchronize = () => {
      const dialogs = [...document.querySelectorAll<HTMLElement>(selector)].filter(visible);
      const next = dialogs.at(-1) || null;
      if (next === current) return;
      const closed = current;
      current = next;
      if (closed && !closed.isConnected) {
        const origin = previous.get(closed);
        previous.delete(closed);
        if (origin?.isConnected && (!next || next.contains(origin)))
          origin.focus({ preventScroll: true });
      }
      if (next && !previous.has(next)) {
        previous.set(
          next,
          document.activeElement instanceof HTMLElement ? document.activeElement : null,
        );
        if (!next.contains(document.activeElement)) {
          next.tabIndex = -1;
          (candidates(next)[0] || next).focus({ preventScroll: true });
        }
      }
    };
    const observer = new MutationObserver(synchronize);
    observer.observe(document.body, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ["open", "hidden", "aria-modal"],
    });
    const trap = (event: KeyboardEvent) => {
      const tab =
        event.target instanceof HTMLElement
          ? event.target.closest<HTMLElement>('[role="tab"]')
          : null;
      if (
        tab &&
        !event.isComposing &&
        ["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)
      ) {
        const tabs = [
          ...(tab
            .closest('[role="tablist"]')
            ?.querySelectorAll<HTMLButtonElement>('[role="tab"]:not(:disabled)') || []),
        ].filter(visible);
        const position = tabs.indexOf(tab as HTMLButtonElement);
        if (tabs.length && position >= 0) {
          event.preventDefault();
          const next =
            tabs[
              event.key === "Home"
                ? 0
                : event.key === "End"
                  ? tabs.length - 1
                  : (position + (event.key === "ArrowRight" ? 1 : -1) + tabs.length) % tabs.length
            ];
          next.focus();
          next.click();
        }
        return;
      }
      if (!current || event.key !== "Tab") return;
      // Tab is remote shell input, not dialog navigation, inside xterm.
      if (event.target instanceof HTMLElement && event.target.closest(".xterm")) return;
      const items = candidates(current);
      const first = items[0] || current,
        last = items.at(-1) || current;
      if (
        !current.contains(document.activeElement) ||
        (!event.shiftKey && document.activeElement === last) ||
        (event.shiftKey && document.activeElement === first)
      ) {
        event.preventDefault();
        (event.shiftKey ? last : first).focus();
      }
    };
    document.addEventListener("keydown", trap, true);
    synchronize();
    return () => {
      observer.disconnect();
      document.removeEventListener("keydown", trap, true);
    };
  }, []);
  return null;
}
