<script lang="ts">
  import type { Cipher } from "../lib/ciphers/types";
  import { link } from "../lib/router";
  import Converter from "./Converter.svelte";
  import Badge from "./Badge.svelte";

  let { cipher }: { cipher: Cipher } = $props();
</script>

<section class="head wrap">
  <a class="back eyebrow reveal" href="/" use:link>← Catalogue</a>
  <div class="head-row reveal" style="animation-delay: 80ms">
    <span class="idx display">{cipher.index}</span>
    <div class="head-text">
      <h1 class="title display">{cipher.name}</h1>
      <p class="tag">{cipher.tagline}</p>
      <div class="badges">
        <Badge label={cipher.vendor} />
        {#if cipher.reversible}
          <Badge label="Reversible · keyless" />
        {/if}
        {#if cipher.keyed}
          <Badge label="Keyed" tone="accent" />
        {/if}
        {#if cipher.status === "planned"}
          <Badge label="Planned" tone="muted" />
        {/if}
      </div>
    </div>
  </div>
</section>

<div class="body wrap">
  <div class="main-col reveal" style="animation-delay: 160ms">
    {#if cipher.status === "available"}
      <Converter {cipher} />
    {:else}
      <div class="teaser">
        <p class="eyebrow accent">Coming soon</p>
        <p class="teaser-text">
          {cipher.name} is not implemented yet. When it lands it will run fully in your browser,
          just like the rest of the catalogue.
        </p>
      </div>
    {/if}
  </div>

  <aside class="notes reveal" style="animation-delay: 240ms">
    <p class="eyebrow">About this format</p>
    <ul>
      {#each cipher.notes as note}
        <li>{note}</li>
      {/each}
    </ul>
    {#if cipher.keyed && !cipher.reversible}
      <div class="warn mono">
        Keep the {(cipher.keyLabel ?? "key").toLowerCase()} secret; anyone who has it can decrypt
        every value.
      </div>
    {/if}

    {#if cipher.links && cipher.links.length > 0}
      <div class="links">
        <p class="eyebrow">Source &amp; tooling</p>
        {#each cipher.links as l (l.url)}
          <a class="src" href={l.url} target="_blank" rel="noopener noreferrer">
            <span class="src-label mono">{l.label}</span>
            <span class="src-arrow" aria-hidden="true">↗</span>
          </a>
          {#if l.note}
            <p class="src-note">{l.note}</p>
          {/if}
        {/each}
      </div>
    {/if}
  </aside>
</div>

<style>
  .head {
    padding-block: clamp(0.3rem, 1vw, 0.6rem) clamp(0.8rem, 2vw, 1.2rem);
  }
  .back {
    display: inline-block;
    color: var(--ink-2);
    margin-bottom: 0.55rem;
    transition: color 0.15s ease;
  }
  .back:hover {
    color: var(--accent);
  }
  .head-row {
    display: flex;
    gap: clamp(1rem, 4vw, 2.5rem);
    align-items: flex-start;
    border-bottom: 1px solid var(--line);
    padding-bottom: clamp(0.4rem, 1.2vw, 0.7rem);
  }
  .idx {
    display: grid;
    place-items: center;
    flex: 0 0 auto;
    width: clamp(3rem, 8vw, 4.6rem);
    height: clamp(3rem, 8vw, 4.6rem);
    border-radius: var(--radius);
    background: var(--accent-tint);
    font-size: clamp(1.4rem, 4vw, 2.2rem);
    color: var(--accent);
    line-height: 1;
  }
  .title {
    font-size: clamp(2rem, 6vw, 3.6rem);
  }
  .tag {
    color: var(--ink-2);
    margin-top: 0.6rem;
    font-size: clamp(0.95rem, 2vw, 1.15rem);
    max-width: 52ch;
  }
  .badges {
    display: flex;
    gap: 0.45rem;
    flex-wrap: wrap;
    margin-top: 0.7rem;
  }
  .body {
    display: grid;
    grid-template-columns: minmax(0, 1.55fr) minmax(0, 1fr);
    gap: clamp(1.6rem, 5vw, 3.5rem);
    padding-top: clamp(0.3rem, 0.8vw, 0.6rem);
    align-items: start;
  }
  .notes {
    background: var(--paper-2);
    border: 1px solid var(--line);
    border-radius: var(--radius);
    box-shadow: var(--shadow-sm);
    padding: clamp(1.3rem, 3vw, 1.8rem);
    position: sticky;
    top: 7.5rem;
  }
  .notes ul {
    list-style: none;
    padding: 0;
    margin-top: 1rem;
    display: flex;
    flex-direction: column;
    gap: 1rem;
  }
  .notes li {
    position: relative;
    padding-left: 1.4rem;
    font-size: 0.92rem;
    color: var(--ink-2);
    line-height: 1.5;
  }
  .notes li::before {
    content: "/";
    position: absolute;
    left: 0;
    color: var(--accent);
    font-weight: 700;
  }
  .warn {
    margin-top: 1.4rem;
    padding: 0.9rem 1rem;
    border-radius: var(--radius-sm);
    background: var(--accent-tint);
    font-size: 0.74rem;
    line-height: 1.5;
    color: var(--accent-press);
  }
  .links {
    margin-top: 1.6rem;
    padding-top: 1.3rem;
    border-top: 1px solid var(--line);
  }
  .src {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 0.75rem;
    margin-top: 0.9rem;
    padding: 0.75rem 1rem;
    border: 1px solid var(--line-2);
    border-radius: var(--radius-sm);
    color: var(--ink);
    transition:
      border-color 0.15s ease,
      background 0.15s ease,
      color 0.15s ease;
  }
  .src:hover {
    border-color: var(--accent);
    background: var(--accent-tint);
    color: var(--accent);
  }
  .src-label {
    font-size: 0.78rem;
    word-break: break-all;
  }
  .src-arrow {
    flex: 0 0 auto;
    font-size: 0.95rem;
    color: var(--ink-3);
  }
  .src:hover .src-arrow {
    color: var(--accent);
  }
  .src-note {
    margin-top: 0.5rem;
    font-size: 0.8rem;
    color: var(--ink-2);
  }
  .teaser {
    border: 1px dashed var(--line-2);
    border-radius: var(--radius);
    padding: clamp(1.8rem, 5vw, 3rem);
    background: var(--paper-2);
  }
  .teaser-text {
    margin-top: 0.9rem;
    color: var(--ink-2);
    max-width: 46ch;
  }
  @media (max-width: 820px) {
    .body {
      grid-template-columns: 1fr;
    }
  }
</style>
