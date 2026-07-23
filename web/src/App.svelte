<script lang="ts">
  import type { CatalogueEntry } from "./lib/ciphers/types";
  import { path, link } from "./lib/router";
  import { findEntry, isConverter } from "./lib/ciphers/registry";
  import Header from "./components/Header.svelte";
  import Footer from "./components/Footer.svelte";
  import Home from "./components/Home.svelte";
  import CipherPage from "./components/CipherPage.svelte";
  import ExplainerPage from "./components/ExplainerPage.svelte";

  type Route =
    | { name: "home" }
    | { name: "entry"; entry: CatalogueEntry }
    | { name: "notfound" };

  function resolve(p: string): Route {
    const clean = p.replace(/\/+$/, "") || "/";
    if (clean === "/") return { name: "home" };
    const id = clean.slice(1);
    const entry = id.includes("/") ? undefined : findEntry(id);
    if (entry) return { name: "entry", entry };
    return { name: "notfound" };
  }

  const route = $derived(resolve($path));
  const routeKey = $derived(route.name === "entry" ? route.entry.id : route.name);

  $effect(() => {
    const base = "Network Secret";
    document.title =
      route.name === "entry"
        ? `${route.entry.name} · ${base}`
        : route.name === "notfound"
          ? `Not found · ${base}`
          : `${base}: network device secret toolkit`;
  });
</script>

<div class="page">
  <Header />
  <main>
    {#key routeKey}
      {#if route.name === "home"}
        <Home />
      {:else if route.name === "entry" && isConverter(route.entry)}
        <CipherPage cipher={route.entry} />
      {:else if route.name === "entry" && route.entry.kind === "explainer"}
        <ExplainerPage explainer={route.entry} />
      {:else}
        <section class="nf wrap">
          <p class="eyebrow accent">Error 404</p>
          <h1 class="display nf-title">Not found</h1>
          <p class="nf-text">That format isn’t in the catalogue.</p>
          <a class="eyebrow back" href="/" use:link>← Catalogue</a>
        </section>
      {/if}
    {/key}
  </main>
  <Footer />
</div>

<style>
  .page {
    display: flex;
    flex-direction: column;
    min-height: 100vh;
  }
  main {
    flex: 1;
  }
  .nf {
    padding-block: clamp(3rem, 12vw, 8rem);
  }
  .nf-title {
    font-size: clamp(2.8rem, 10vw, 6rem);
    margin: 1rem 0;
  }
  .nf-text {
    color: var(--ink-2);
    margin-bottom: 1.6rem;
  }
  .back {
    color: var(--ink-2);
    transition: color 0.15s ease;
  }
  .back:hover {
    color: var(--accent);
  }
</style>
