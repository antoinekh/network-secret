<script lang="ts">
  import { path, link } from "../lib/router";
  import { registry } from "../lib/ciphers/registry";
  import { theme, toggleTheme } from "../lib/theme";

  function isActive(current: string, href: string): boolean {
    return (current.replace(/\/+$/, "") || "/") === href;
  }
</script>

<header class="hdr">
  <div class="wrap top">
    <a class="brand" href="/" use:link aria-label="Vendor Secrets home">
      <span class="mark mono">//</span>
      <span class="word display">Vendor Secrets</span>
    </a>
    <div class="top-right">
      <span class="meta mono">Runs locally · no backend</span>
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
      {#each registry as c (c.id)}
        {#if c.status === "available"}
          <a
            class="tab"
            class:active={isActive($path, `/c/${c.id}`)}
            href={`/c/${c.id}`}
            use:link>{c.name}</a
          >
        {:else}
          <span class="tab disabled">{c.name}<span class="soon">soon</span></span>
        {/if}
      {/each}
    </div>
  </nav>
</header>

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
    padding-block: 1rem 0.85rem;
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
    font-size: 1.22rem;
    font-weight: 700;
  }
  .top-right {
    display: flex;
    align-items: center;
    gap: 0.9rem;
  }
  .meta {
    font-size: 0.68rem;
    font-weight: 700;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    color: var(--accent);
  }
  .theme {
    background: var(--paper-2);
    border: 1px solid var(--line-2);
    border-radius: 999px;
    padding: 0.42em 0.9em;
    font-size: 0.68rem;
    letter-spacing: 0.04em;
    color: var(--ink-2);
    white-space: nowrap;
    box-shadow: var(--shadow-sm);
    transition:
      color 0.15s ease,
      border-color 0.15s ease,
      transform 0.15s ease;
  }
  .theme:hover {
    color: var(--accent);
    border-color: var(--accent);
    transform: translateY(-1px);
  }
  .nav-wrap {
    padding-bottom: 0.7rem;
  }
  .nav {
    display: flex;
    gap: 0.4rem;
    overflow-x: auto;
    scrollbar-width: none;
  }
  .nav::-webkit-scrollbar {
    display: none;
  }
  .tab {
    flex: 0 0 auto;
    padding: 0.45rem 0.9rem;
    border-radius: 999px;
    font-family: var(--font-mono);
    font-size: 0.72rem;
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
  .tab.disabled {
    color: var(--ink-3);
    opacity: 0.6;
    cursor: default;
    display: inline-flex;
    align-items: center;
    gap: 0.45em;
  }
  .soon {
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
  }
</style>
