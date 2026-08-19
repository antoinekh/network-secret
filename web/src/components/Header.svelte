<script lang="ts">
  import { path, link } from "../lib/router";
  import { catalogue } from "../lib/ciphers/registry";
  import { vendorGroups } from "../lib/nav";
  import { theme, toggleTheme } from "../lib/theme";

  const groups = vendorGroups(catalogue);
  let open = $state<string | null>(null);

  function isActive(current: string, href: string): boolean {
    return (current.replace(/\/+$/, "") || "/") === href;
  }

  function groupIsActive(vendor: string): boolean {
    const group = groups.find((g) => g.vendor === vendor);
    return group?.entries.some((e) => isActive($path, `/${e.id}`)) ?? false;
  }

  function onKeydown(event: KeyboardEvent) {
    if (event.key === "Escape") open = null;
  }
</script>

<header class="hdr">
  <div class="wrap top">
    <a class="brand" href="/" use:link aria-label="Network Secret home">
      <span class="mark mono">//</span>
      <span class="word display">Network Secret</span>
    </a>
    <div class="top-right">
      <span class="meta mono">Runs locally · no backend</span>
      <a
        class="repo mono"
        href="https://github.com/antoinekh/network-secret"
        target="_blank"
        rel="noopener noreferrer"
        aria-label="Source code on GitHub (opens in a new tab)"
        ><span class="repo-label">Source</span> <span aria-hidden="true">↗</span></a
      >
      <button
        class="theme mono"
        onclick={toggleTheme}
        aria-label={$theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
        title={$theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
      >
        {$theme === "dark" ? "☀ Light" : "☾ Dark"}
      </button>
    </div>
  </div>
  <nav class="nav-wrap" aria-label="Sections">
    <div class="wrap nav">
      <a class="tab" class:active={isActive($path, "/")} href="/" use:link>Catalogue</a>
      {#each groups as group (group.vendor)}
        <div
          class="group"
          role="none"
          onmouseenter={() => (open = group.vendor)}
          onmouseleave={() => (open = null)}
        >
          <button
            class="tab"
            class:active={groupIsActive(group.vendor)}
            aria-haspopup="menu"
            aria-expanded={open === group.vendor}
            onclick={(e) => {
              e.stopPropagation();
              open = open === group.vendor ? null : group.vendor;
            }}
            onfocus={() => (open = group.vendor)}
          >
            {group.vendor}<span class="caret" aria-hidden="true">▾</span>
          </button>
          {#if open === group.vendor}
            <div class="menu" role="menu">
              {#each group.entries as entry (entry.id)}
                {#if entry.kind === "explainer"}
                  <a
                    class="item"
                    role="menuitem"
                    class:current={isActive($path, `/${entry.id}`)}
                    href={`/${entry.id}`}
                    use:link>{entry.name}<span class="pill">doc</span></a
                  >
                {:else if entry.status === "available"}
                  <a
                    class="item"
                    role="menuitem"
                    class:current={isActive($path, `/${entry.id}`)}
                    href={`/${entry.id}`}
                    use:link
                    >{entry.name}{#if entry.oneWay}<span class="pill">one-way</span>{/if}</a
                  >
                {:else}
                  <span class="item disabled" role="menuitem"
                    >{entry.name}<span class="pill">soon</span></span
                  >
                {/if}
              {/each}
            </div>
          {/if}
        </div>
      {/each}
    </div>
  </nav>
</header>

<svelte:window onkeydown={onKeydown} onclick={() => (open = null)} />

<style>
  .hdr {
    position: sticky;
    top: 0;
    z-index: 20;
    background: color-mix(in srgb, var(--paper) 82%, transparent);
    backdrop-filter: saturate(1.4) blur(12px);
    border-bottom: 1px solid var(--line);
  }
  .top {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 1rem;
    padding-block: 0.7rem 0.6rem;
  }
  .brand {
    display: inline-flex;
    align-items: center;
    gap: 0.6rem;
  }
  .mark {
    display: grid;
    place-items: center;
    width: 1.9rem;
    height: 1.9rem;
    border-radius: 9px;
    background: var(--accent);
    color: #fff;
    font-weight: 700;
    font-size: 0.85rem;
    box-shadow: var(--shadow-sm);
  }
  .word {
    font-size: clamp(1.05rem, 2.2vw, 1.32rem);
    font-weight: 700;
    line-height: 1.1;
  }
  .top-right {
    display: flex;
    align-items: center;
    gap: 0.9rem;
  }
  .meta {
    font-size: 0.74rem;
    font-weight: 700;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    color: var(--accent);
  }
  .theme,
  .repo {
    background: var(--paper-2);
    border: 1px solid var(--line-2);
    border-radius: 999px;
    padding: 0.42em 0.9em;
    font-size: 0.74rem;
    letter-spacing: 0.04em;
    color: var(--ink-2);
    white-space: nowrap;
    box-shadow: var(--shadow-sm);
    transition:
      color 0.15s ease,
      border-color 0.15s ease,
      transform 0.15s ease;
  }
  .theme:hover,
  .repo:hover {
    color: var(--accent);
    border-color: var(--accent);
    transform: translateY(-1px);
  }
  .repo {
    display: inline-flex;
    align-items: center;
  }
  .nav-wrap {
    padding-bottom: 0.4rem;
  }
  .nav {
    display: flex;
    gap: 0.4rem;
    flex-wrap: wrap;
  }
  .nav::-webkit-scrollbar {
    display: none;
  }
  .group {
    position: relative;
    flex: 0 0 auto;
  }
  .group .tab {
    display: inline-flex;
    align-items: center;
    gap: 0.4em;
    border: none;
    background: transparent;
    cursor: pointer;
  }
  .caret {
    font-size: 0.6rem;
    opacity: 0.7;
  }
  .menu {
    position: absolute;
    top: calc(100% + 0.35rem);
    left: 0;
    z-index: 30;
    min-width: 14rem;
    display: flex;
    flex-direction: column;
    padding: 0.35rem;
    background: var(--paper-2);
    border: 1px solid var(--line);
    border-radius: var(--radius-sm);
    box-shadow: var(--shadow-md);
  }
  .item {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 0.6em;
    padding: 0.5rem 0.7rem;
    border-radius: var(--radius-sm);
    font-family: var(--font-mono);
    font-size: 0.78rem;
    color: var(--ink-2);
    white-space: nowrap;
  }
  a.item:hover {
    color: var(--ink);
    background: var(--paper-3);
  }
  .item.current {
    color: #fff;
    background: var(--accent);
  }
  .item.disabled {
    color: var(--ink-3);
    opacity: 0.6;
    cursor: default;
  }
  .tab {
    flex: 0 0 auto;
    padding: 0.45rem 0.9rem;
    border-radius: 999px;
    font-family: var(--font-mono);
    font-size: 0.78rem;
    letter-spacing: 0.02em;
    color: var(--ink-2);
    white-space: nowrap;
    transition:
      color 0.15s ease,
      background 0.15s ease;
  }
  a.tab:hover {
    color: var(--ink);
    background: var(--paper-3);
  }
  .tab.active {
    color: #fff;
    background: var(--accent);
  }
  .pill {
    font-size: 0.56rem;
    letter-spacing: 0.06em;
    border-radius: 999px;
    background: var(--paper-3);
    padding: 0.15em 0.5em;
  }
  @media (max-width: 560px) {
    .meta {
      display: none;
    }
    .repo-label {
      display: none;
    }
  }
</style>
