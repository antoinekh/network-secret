import { writable } from "svelte/store";

/** Current pathname, as a Svelte store. */
export const path = writable(window.location.pathname);

export function navigate(to: string): void {
  if (to !== window.location.pathname) {
    window.history.pushState({}, "", to);
    path.set(to);
  }
  window.scrollTo({ top: 0 });
}

window.addEventListener("popstate", () => {
  path.set(window.location.pathname);
});

/**
 * Svelte action: turn an internal `<a href="/...">` into a client-side route
 * change, while leaving modifier-clicks and external links to the browser.
 */
export function link(node: HTMLAnchorElement) {
  const onClick = (event: MouseEvent) => {
    if (
      event.defaultPrevented ||
      event.button !== 0 ||
      event.metaKey ||
      event.ctrlKey ||
      event.shiftKey ||
      event.altKey
    ) {
      return;
    }
    const href = node.getAttribute("href");
    if (!href || !href.startsWith("/")) {
      return;
    }
    event.preventDefault();
    navigate(href);
  };
  node.addEventListener("click", onClick);
  return {
    destroy() {
      node.removeEventListener("click", onClick);
    },
  };
}
