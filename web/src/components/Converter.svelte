<script lang="ts">
  import type { Cipher } from "../lib/ciphers/types";
  import { unwrapValue } from "../lib/normalize";
  import CopyButton from "./CopyButton.svelte";

  let { cipher }: { cipher: Cipher } = $props();

  type Mode = "decode" | "encode" | "verify";

  const oneWay = $derived(cipher.oneWay === true);
  // One-way formats have nothing to decode, so their pair is Hash / Verify.
  const modes = $derived<Mode[]>(oneWay ? ["encode", "verify"] : ["decode", "encode"]);

  // "Encode" reads as "Hash" for a one-way format, so the label is a function
  // of both the mode and the cipher.
  function tabLabel(m: Mode): string {
    if (m === "encode") return oneWay ? "Hash" : "Encode";
    return m === "decode" ? "Decode" : "Verify";
  }

  let mode = $state<Mode>("decode");
  let input = $state("");
  let candidate = $state("");
  let key = $state("");
  let showKey = $state(false);
  let busy = $state(false);
  let result = $state<{ ok: boolean; value: string } | null>(null);

  // A one-way cipher starts on Hash; everything else starts on Decode.
  // This only resets `mode`: it relies on App.svelte mounting this component
  // under {#key routeKey}, which remounts it on every route change so
  // `input`, `candidate` and `key` also start fresh. If Converter is ever
  // reused without that wrapper, those fields will need resetting here too.
  $effect(() => {
    if (!modes.includes(mode)) {
      mode = modes[0];
      result = null;
    }
  });

  const inputLabel = $derived(
    mode === "decode"
      ? `Encoded value${cipher.magic ? ` (${cipher.magic}…)` : ""}`
      : mode === "verify"
        ? `Hash${cipher.magic ? ` (${cipher.magic}…)` : ""}`
        : "Cleartext",
  );
  const runLabel = $derived(
    mode === "decode" ? "Decode" : mode === "verify" ? "Verify" : oneWay ? "Hash" : "Encode",
  );
  const placeholder = $derived(
    mode === "encode" ? "secret" : (cipher.example?.encoded ?? `${cipher.magic}…`),
  );

  function setMode(next: Mode) {
    if (next === mode) return;
    mode = next;
    result = null;
  }

  async function run() {
    busy = true;
    result = null;
    try {
      // Config values are pasted wrapped in quotes; strip them for decode and
      // for the key. Plaintext to encode is left exactly as typed.
      const k = unwrapValue(key) || undefined;
      if (mode === "verify") {
        if (!cipher.verify) throw new Error("This format cannot verify");
        const match = await cipher.verify(unwrapValue(input), candidate);
        result = { ok: true, value: match ? "Match" : "No match" };
      } else if (mode === "decode") {
        result = { ok: true, value: await cipher.decode(unwrapValue(input), k) };
      } else {
        result = { ok: true, value: await cipher.encode(input, k) };
      }
    } catch (e) {
      result = { ok: false, value: e instanceof Error ? e.message : String(e) };
    } finally {
      busy = false;
    }
  }

  function fillExample() {
    const ex = cipher.example;
    if (!ex) return;
    input = mode === "encode" ? ex.plaintext : ex.encoded;
    if (mode === "verify") candidate = ex.plaintext;
    if (ex.key) key = ex.key;
    void run();
  }
</script>

<section class="cv">
  <div class="modes" role="tablist" aria-label="Mode">
    {#each modes as m (m)}
      <button
        role="tab"
        aria-selected={mode === m}
        class:active={mode === m}
        onclick={() => setMode(m)}>{tabLabel(m)}</button
      >
    {/each}
  </div>

  <form
    onsubmit={(e) => {
      e.preventDefault();
      void run();
    }}
  >
    <label class="field">
      <span class="lab eyebrow">{inputLabel}</span>
      <textarea
        class="mono in"
        bind:value={input}
        rows="3"
        {placeholder}
        spellcheck="false"
        autocapitalize="off"
        autocomplete="off"
      ></textarea>
    </label>

    {#if mode === "verify"}
      <label class="field">
        <span class="lab eyebrow">Cleartext to test</span>
        <input
          class="mono in"
          bind:value={candidate}
          placeholder="secret"
          spellcheck="false"
          autocapitalize="off"
          autocomplete="off"
        />
      </label>
    {/if}

    {#if cipher.keyed}
      <label class="field">
        <span class="lab eyebrow">{cipher.keyLabel ?? "Key"}</span>
        <span class="key-wrap">
          <input
            class="mono in"
            type={showKey ? "text" : "password"}
            bind:value={key}
            placeholder={(cipher.keyLabel ?? "key").toLowerCase()}
            spellcheck="false"
            autocomplete="off"
          />
          <button
            type="button"
            class="ghost"
            onclick={() => (showKey = !showKey)}
            aria-label={showKey ? "Hide key" : "Show key"}>{showKey ? "Hide" : "Show"}</button
          >
        </span>
      </label>
    {/if}

    <div class="actions">
      <button class="run" type="submit" disabled={busy || !input || (mode === "verify" && !candidate)}>
        {busy ? "Working…" : runLabel}
      </button>
      {#if cipher.example}
        <button type="button" class="ghost" onclick={fillExample}>Try example</button>
      {/if}
    </div>
  </form>

  <div aria-live="polite">
    {#if result}
      {#if result.ok}
        <div class="out ok">
          <span class="lab eyebrow">Result</span>
          <div class="out-row">
            <code class="mono val">{result.value || "(empty string)"}</code>
            <CopyButton text={result.value} />
          </div>
        </div>
      {:else}
        <div class="out err">
          <span class="lab eyebrow">Error</span>
          <p class="mono">{result.value}</p>
        </div>
      {/if}
    {/if}
  </div>

  {#if mode === "encode" && cipher.reversible}
    <p class="hint mono">
      Output varies on every run (random filler); all forms decode to the same value.
    </p>
  {/if}

  {#if mode === "encode" && oneWay}
    <p class="hint mono">
      A fresh random salt is drawn each run, so the same password hashes differently every time.
      Use Verify to test a password against an existing hash.
    </p>
  {/if}
</section>

<style>
  .cv {
    border: 1px solid var(--line);
    background: var(--paper-2);
    border-radius: var(--radius);
    box-shadow: var(--shadow-md);
    overflow: hidden;
  }
  .modes {
    display: flex;
    gap: 0.3rem;
    padding: 0.6rem;
    background: var(--paper-3);
    border-bottom: 1px solid var(--line);
  }
  .modes button {
    flex: 0 0 auto;
    background: transparent;
    border: none;
    border-radius: 999px;
    padding: 0.5rem 1.3rem;
    font-family: var(--font-mono);
    font-size: 0.74rem;
    letter-spacing: 0.04em;
    color: var(--ink-3);
    transition:
      color 0.15s ease,
      background 0.15s ease;
  }
  .modes button:hover {
    color: var(--ink);
  }
  .modes button.active {
    color: #fff;
    background: var(--accent);
    box-shadow: var(--shadow-sm);
  }
  form {
    padding: clamp(1.2rem, 3vw, 1.9rem);
    display: flex;
    flex-direction: column;
    gap: 1.1rem;
  }
  .field {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }
  .lab {
    color: var(--ink-2);
  }
  .in {
    width: 100%;
    background: var(--paper);
    border: 1px solid var(--line-2);
    border-radius: var(--radius-sm);
    padding: 0.85rem 1rem;
    font-size: 0.92rem;
    line-height: 1.5;
    color: var(--ink);
    resize: vertical;
    transition:
      border-color 0.15s ease,
      box-shadow 0.15s ease;
  }
  .in:focus {
    border-color: var(--accent);
    outline: none;
    box-shadow: 0 0 0 3px var(--accent-tint);
  }
  textarea.in {
    word-break: break-all;
  }
  .key-wrap {
    display: flex;
    gap: 0.5rem;
  }
  .key-wrap .in {
    flex: 1;
  }
  .actions {
    display: flex;
    gap: 0.7rem;
    align-items: center;
    flex-wrap: wrap;
  }
  .run {
    background: var(--accent);
    color: #fff;
    border: 1px solid var(--accent);
    border-radius: 999px;
    padding: 0.72rem 1.8rem;
    font-family: var(--font-mono);
    font-size: 0.78rem;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    box-shadow: var(--shadow-sm);
    transition:
      background 0.15s ease,
      transform 0.15s ease,
      box-shadow 0.15s ease;
  }
  .run:hover:not(:disabled) {
    background: var(--accent-press);
    transform: translateY(-1px);
    box-shadow: var(--shadow-md);
  }
  .run:disabled {
    opacity: 0.4;
    cursor: not-allowed;
  }
  .ghost {
    background: transparent;
    border: 1px solid var(--line-2);
    border-radius: 999px;
    padding: 0.72rem 1.3rem;
    font-family: var(--font-mono);
    font-size: 0.72rem;
    letter-spacing: 0.04em;
    text-transform: uppercase;
    color: var(--ink-2);
    transition:
      color 0.15s ease,
      border-color 0.15s ease;
  }
  .ghost:hover {
    color: var(--accent);
    border-color: var(--accent);
  }
  .out {
    margin: 0 clamp(1.2rem, 3vw, 1.9rem) clamp(1.2rem, 3vw, 1.9rem);
    padding: 1.1rem 1.2rem;
    background: var(--paper-3);
    border-radius: var(--radius-sm);
    display: flex;
    flex-direction: column;
    gap: 0.6rem;
    animation: fade 0.35s ease;
  }
  .out.ok {
    background: var(--accent-tint);
  }
  .out .lab {
    color: var(--ink-2);
  }
  .out.err .lab {
    color: var(--accent);
  }
  .out-row {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 1rem;
  }
  .val {
    font-size: 1.05rem;
    font-weight: 500;
    word-break: break-all;
    color: var(--ink);
  }
  .out.err p {
    color: var(--accent-press);
    font-size: 0.85rem;
    word-break: break-word;
  }
  .hint {
    padding: 0 clamp(1.2rem, 3vw, 1.9rem) clamp(1.2rem, 3vw, 1.7rem);
    font-size: 0.72rem;
    color: var(--ink-3);
  }
  @keyframes fade {
    from {
      opacity: 0;
      transform: translateY(6px);
    }
  }
</style>
