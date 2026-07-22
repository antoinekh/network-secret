<script lang="ts">
  import type { ExplainerEntry } from "../lib/ciphers/types";
  import { link } from "../lib/router";
  import Badge from "./Badge.svelte";

  let { explainer }: { explainer: ExplainerEntry } = $props();

  const Prose = $derived(explainer.component);
</script>

<section class="head wrap">
  <a class="back eyebrow reveal" href="/" use:link>← Catalogue</a>
  <div class="head-row reveal" style="animation-delay: 80ms">
    <span class="idx display">{explainer.index}</span>
    <div class="head-text">
      <h1 class="title display">{explainer.name}</h1>
      <p class="tag">{explainer.tagline}</p>
      <div class="badges">
        {#each explainer.badges as badge (badge.label)}
          <Badge label={badge.label} tone={badge.tone} />
        {/each}
      </div>
    </div>
  </div>
</section>

<div class="body wrap">
  <article class="prose reveal" style="animation-delay: 160ms">
    <Prose />
  </article>

  <aside class="side reveal" style="animation-delay: 240ms">
    <p class="eyebrow">At a glance</p>
    <dl class="facts">
      {#each explainer.facts as fact (fact.term)}
        <div>
          <dt>{fact.term}</dt>
          <dd class:mono={fact.mono}>{fact.value}</dd>
        </div>
      {/each}
    </dl>

    {#if explainer.related.length > 0}
      <div class="side-links">
        <p class="eyebrow">Related</p>
        {#each explainer.related as r (r.href)}
          <a class="src" href={r.href} use:link>
            <span class="src-label mono">{r.label}</span>
            <span class="src-arrow" aria-hidden="true">→</span>
          </a>
          <p class="src-note">{r.note}</p>
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
    max-width: 60ch;
  }
  .badges {
    display: flex;
    gap: 0.45rem;
    flex-wrap: wrap;
    margin-top: 0.7rem;
  }
  .body {
    display: grid;
    grid-template-columns: minmax(0, 1.7fr) minmax(0, 1fr);
    gap: clamp(1.6rem, 5vw, 3.5rem);
    padding-top: clamp(0.8rem, 2vw, 1.4rem);
    align-items: start;
  }

  /* The prose body lives in a child component, so its elements are styled
     globally under the scoped .prose wrapper. */
  .prose {
    max-width: 68ch;
  }
  .prose :global(.lede) {
    font-size: clamp(1.02rem, 2vw, 1.2rem);
    line-height: 1.55;
    color: var(--ink);
  }
  .prose :global(p) {
    color: var(--ink-2);
    line-height: 1.65;
    margin-top: 1rem;
  }
  .prose :global(h2) {
    font-family: var(--font-display, inherit);
    font-size: clamp(1.25rem, 3vw, 1.7rem);
    margin-top: 2.4rem;
    padding-top: 1.2rem;
    border-top: 1px solid var(--line);
    color: var(--ink);
  }
  .prose :global(strong) {
    color: var(--ink);
  }
  .prose :global(code) {
    font-family: var(--font-mono);
    font-size: 0.86em;
    background: var(--paper-3);
    padding: 0.1em 0.35em;
    border-radius: 6px;
    color: var(--ink);
  }
  .prose :global(.callout) {
    margin-top: 1.6rem;
    padding: clamp(1.1rem, 3vw, 1.5rem);
    border: 1px solid var(--line-2);
    border-left: 3px solid var(--accent);
    border-radius: var(--radius-sm);
    background: var(--paper-2);
    box-shadow: var(--shadow-sm);
  }
  .prose :global(.callout-title) {
    font-size: 0.74rem;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    color: var(--accent);
    margin-bottom: 0.6rem;
  }
  .prose :global(.callout p) {
    margin-top: 0;
    color: var(--ink-2);
  }
  .prose :global(.callout em) {
    color: var(--ink);
    font-style: italic;
  }
  .prose :global(.steps) {
    list-style: none;
    padding: 0;
    margin-top: 1.2rem;
    display: flex;
    flex-direction: column;
    gap: 0.9rem;
  }
  .prose :global(.steps li) {
    display: grid;
    grid-template-columns: minmax(6.5rem, auto) 1fr;
    gap: 0.4rem 1.2rem;
    padding: 0.9rem 1.1rem;
    background: var(--paper-2);
    border: 1px solid var(--line);
    border-radius: var(--radius-sm);
  }
  .prose :global(.step-k) {
    font-size: 0.72rem;
    letter-spacing: 0.04em;
    text-transform: uppercase;
    color: var(--accent);
    padding-top: 0.15rem;
  }
  .prose :global(.step-v) {
    color: var(--ink-2);
    line-height: 1.55;
    font-size: 0.94rem;
  }
  .prose :global(.step-v em) {
    color: var(--ink);
    font-style: normal;
    font-weight: 600;
  }
  .prose :global(.fineprint) {
    font-size: 0.86rem;
    color: var(--ink-3);
  }
  .prose :global(.diagram),
  .prose :global(.code) {
    margin-top: 1.1rem;
    padding: 1.1rem 1.2rem;
    background: var(--paper-3);
    border: 1px solid var(--line);
    border-radius: var(--radius-sm);
    font-size: 0.8rem;
    line-height: 1.7;
    color: var(--ink);
    overflow-x: auto;
    white-space: pre;
  }
  .prose :global(.code) {
    line-height: 1.6;
  }
  .prose :global(.takeaways) {
    margin-top: 1.1rem;
    padding: 0;
    list-style: none;
    display: flex;
    flex-direction: column;
    gap: 0.9rem;
  }
  .prose :global(.takeaways li) {
    position: relative;
    padding-left: 1.5rem;
    color: var(--ink-2);
    line-height: 1.6;
  }
  .prose :global(.takeaways li)::before {
    content: "/";
    position: absolute;
    left: 0;
    color: var(--accent);
    font-weight: 700;
  }

  .side {
    background: var(--paper-2);
    border: 1px solid var(--line);
    border-radius: var(--radius);
    box-shadow: var(--shadow-sm);
    padding: clamp(1.3rem, 3vw, 1.8rem);
    position: sticky;
    top: 7.5rem;
  }
  .facts {
    margin: 1rem 0 0;
    display: flex;
    flex-direction: column;
  }
  .facts > div {
    display: flex;
    justify-content: space-between;
    gap: 1rem;
    padding: 0.6rem 0;
    border-bottom: 1px solid var(--line);
  }
  .facts > div:last-child {
    border-bottom: none;
  }
  .facts dt {
    color: var(--ink-3);
    font-size: 0.82rem;
  }
  .facts dd {
    color: var(--ink);
    font-size: 0.9rem;
    text-align: right;
  }
  .side-links {
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
  }
  .src-arrow {
    flex: 0 0 auto;
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
  @media (max-width: 820px) {
    .body {
      grid-template-columns: 1fr;
    }
    .side {
      position: static;
    }
  }
</style>
