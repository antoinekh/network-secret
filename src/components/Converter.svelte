<script lang="ts">
  import type { Cipher } from "../lib/ciphers/types";
  import { unwrapValue } from "../lib/normalize";
  import CopyButton from "./CopyButton.svelte";

  let { cipher }: { cipher: Cipher } = $props();

  type Mode = "decode" | "encode";
  let mode = $state<Mode>("decode");
  let input = $state("");
  let key = $state("");
  let showKey = $state(false);
  let busy = $state(false);
  let result = $state<{ ok: boolean; value: string } | null>(null);

  const inputLabel = $derived(
    mode === "decode"
      ? `Encoded value${cipher.magic ? ` (${cipher.magic}…)` : ""}`
      : "Cleartext",
  );
  const runLabel = $derived(mode === "decode" ? "Decode" : "Encode");
  const placeholder = $derived(
    mode === "decode" ? (cipher.example?.encoded ?? `${cipher.magic}…`) : "secret",
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
      const value =
        mode === "decode"
          ? await cipher.decode(unwrapValue(input), k)
          : await cipher.encode(input, k);
      result = { ok: true, value };
    } catch (e) {
      result = { ok: false, value: e instanceof Error ? e.message : String(e) };
    } finally {
      busy = false;
    }
  }

  function fillExample() {
    const ex = cipher.example;
    if (!ex) return;
    input = mode === "decode" ? ex.encoded : ex.plaintext;
    if (ex.key) key = ex.key;
    void run();
  }
</script>

<section class="cv">
  <div class="modes" role="tablist" aria-label="Mode">
    <button
      role="tab"
      aria-selected={mode === "decode"}
      class:active={mode === "decode"}
      onclick={() => setMode("decode")}>Decode</button
    >
    <button
      role="tab"
      aria-selected={mode === "encode"}
      class:active={mode === "encode"}
      onclick={() => setMode("encode")}>Encode</button
    >
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
      <button class="run" type="submit" disabled={busy || !input}>
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
