<script lang="ts">
  import { link } from "../lib/router";
  import { catalogue } from "../lib/ciphers/registry";
  import Badge from "./Badge.svelte";

  const converters = catalogue.filter((c) => c.kind === "converter");
  const available = converters.filter((c) => c.status === "available").length;
  const planned = converters.filter((c) => c.status === "planned").length;
  const explainers = catalogue.filter((c) => c.kind === "explainer").length;
</script>

<section class="hero wrap">
  <p class="eyebrow reveal" style="animation-delay: 40ms">Network device secret toolkit</p>
  <h1 class="display title">
    <span class="reveal" style="animation-delay: 90ms"
      >Decode <span class="accent">&amp;</span> encode</span
    >
    <span class="reveal" style="animation-delay: 170ms">network device</span>
    <span class="reveal" style="animation-delay: 250ms">secrets.</span>
  </h1>
  <p class="lede reveal" style="animation-delay: 340ms">
    Juniper <span class="mono">$9$</span>, Juniper <span class="mono">$8$</span>, and Nokia
    <span class="mono">custom-hash</span>, computed entirely in your browser. Nothing is ever
    sent to a server.
  </p>
</section>

<section class="catalogue wrap">
  <div class="cat-head reveal" style="animation-delay: 400ms">
    <span class="eyebrow">Catalogue</span>
    <span class="eyebrow">
      {available} available{planned > 0 ? ` · ${planned} planned` : ""}{explainers > 0
        ? ` · ${explainers} explainers`
        : ""}
    </span>
  </div>
  <ul class="list">
    {#each catalogue as c, i (c.id)}
      <li class="reveal" style="animation-delay: {440 + i * 80}ms">
        {#if c.kind === "explainer"}
          <a class="row" href={`/${c.id}`} use:link>
            <span class="idx mono">{c.index}</span>
            <span class="main">
              <span class="name display">{c.name}</span>
              <span class="tag">{c.cardTagline ?? c.tagline}</span>
            </span>
            <span class="badges">
              <Badge label={c.vendor} />
              <Badge label="Doc" tone="muted" />
            </span>
            <span class="arrow" aria-hidden="true">→</span>
          </a>
        {:else if c.status === "available"}
          <a class="row" href={`/${c.id}`} use:link>
            <span class="idx mono">{c.index}</span>
            <span class="main">
              <span class="name display">{c.name}</span>
              <span class="tag">{c.tagline}</span>
            </span>
            <span class="badges">
              <Badge label={c.vendor} />
              {#if c.reversible}
                <Badge label="Reversible" />
              {:else if c.keyed}
                <Badge label="Keyed" tone="accent" />
              {/if}
            </span>
            <span class="arrow" aria-hidden="true">→</span>
          </a>
        {:else}
          <div class="row planned">
            <span class="idx mono">{c.index}</span>
            <span class="main">
              <span class="name display">{c.name}</span>
              <span class="tag">{c.tagline}</span>
            </span>
            <span class="badges">
              <Badge label={c.vendor} />
              <Badge label="Planned" tone="muted" />
            </span>
            <span class="arrow dot" aria-hidden="true">·</span>
          </div>
        {/if}
      </li>
    {/each}
  </ul>
</section>

<style>
  .hero {
    padding-block: clamp(1.6rem, 5vw, 4rem) clamp(2rem, 5vw, 3.5rem);
  }
  .title {
    font-size: clamp(2rem, 6vw, 4rem);
    margin-top: 1.2rem;
    margin-bottom: 1.6rem;
  }
  .title span {
    display: block;
  }
  .lede {
    max-width: 56ch;
    font-size: clamp(1rem, 2.2vw, 1.35rem);
    color: var(--ink-2);
    line-height: 1.5;
  }
  .lede .mono {
    color: var(--ink);
  }
  .cat-head {
    display: flex;
    justify-content: space-between;
    align-items: baseline;
    padding-bottom: 1rem;
  }
  .list {
    list-style: none;
    padding: 0;
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(330px, 1fr));
    gap: 1rem;
  }
  .row {
    display: grid;
    grid-template-columns: auto 1fr;
    grid-template-areas:
      "idx badges"
      "main main"
      "arrow arrow";
    align-items: start;
    gap: 0.6rem 1rem;
    height: 100%;
    padding: 1.4rem 1.5rem;
    background: var(--paper-2);
    border: 1px solid var(--line);
    border-radius: var(--radius);
    box-shadow: var(--shadow-sm);
    transition:
      transform 0.2s cubic-bezier(0.16, 1, 0.3, 1),
      box-shadow 0.2s ease,
      border-color 0.2s ease;
  }
  a.row:hover {
    transform: translateY(-4px);
    box-shadow: var(--shadow-lg);
    border-color: color-mix(in srgb, var(--accent) 40%, var(--line));
  }
  .idx {
    grid-area: idx;
    font-weight: 600;
    font-size: 0.82rem;
    color: var(--ink-3);
    letter-spacing: 0.04em;
  }
  .main {
    grid-area: main;
    display: flex;
    flex-direction: column;
    gap: 0.35rem;
    min-width: 0;
  }
  .name {
    font-size: 1.5rem;
    transition: color 0.18s ease;
  }
  a.row:hover .name {
    color: var(--accent);
  }
  .tag {
    color: var(--ink-2);
    font-size: 0.92rem;
    line-height: 1.45;
  }
  .badges {
    grid-area: badges;
    display: flex;
    gap: 0.4rem;
    flex-wrap: wrap;
    justify-content: flex-end;
  }
  .arrow {
    grid-area: arrow;
    justify-self: start;
    margin-top: 0.4rem;
    display: grid;
    place-items: center;
    width: 2.1rem;
    height: 2.1rem;
    border-radius: 999px;
    background: var(--paper-3);
    font-size: 1.05rem;
    color: var(--ink-2);
    transition:
      transform 0.2s ease,
      color 0.2s ease,
      background 0.2s ease;
  }
  a.row:hover .arrow {
    color: #fff;
    background: var(--accent);
    transform: translateX(4px);
  }
  .planned {
    opacity: 0.7;
    border-style: dashed;
    box-shadow: none;
  }
  .planned .name {
    color: var(--ink-2);
  }
  .arrow.dot {
    background: transparent;
  }
</style>
