<script lang="ts">
  let { text }: { text: string } = $props();
  let copied = $state(false);
  let timer: ReturnType<typeof setTimeout> | undefined;

  async function copy() {
    try {
      await navigator.clipboard.writeText(text);
      copied = true;
      clearTimeout(timer);
      timer = setTimeout(() => (copied = false), 1300);
    } catch {
      /* clipboard blocked; ignore */
    }
  }
</script>

<button class="copy" class:copied onclick={copy} disabled={!text} type="button">
  {copied ? "Copied" : "Copy"}
</button>

<style>
  .copy {
    font-family: var(--font-mono);
    font-size: 0.68rem;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    background: var(--paper-3);
    border: 1px solid var(--line-2);
    border-radius: 999px;
    padding: 0.5em 1em;
    color: var(--ink-2);
    transition:
      color 0.15s ease,
      border-color 0.15s ease,
      background 0.15s ease,
      transform 0.15s ease;
  }
  .copy:hover:not(:disabled) {
    color: var(--accent);
    border-color: var(--accent);
    transform: translateY(-1px);
  }
  .copy:disabled {
    opacity: 0.4;
    cursor: not-allowed;
  }
  .copied {
    color: #fff;
    background: var(--accent);
    border-color: var(--accent);
  }
</style>
