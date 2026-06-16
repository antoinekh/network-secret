<script lang="ts">
  let {
    label,
    tone = "default",
  }: { label: string; tone?: "default" | "accent" | "muted" } = $props();
</script>

<span class="badge {tone}">{label}</span>

<style>
  .badge {
    display: inline-block;
    font-family: var(--font-mono);
    font-size: 0.64rem;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    padding: 0.32em 0.7em;
    border-radius: 999px;
    background: var(--paper-3);
    border: 1px solid transparent;
    color: var(--ink-2);
    white-space: nowrap;
  }
  .accent {
    background: var(--accent-tint);
    color: var(--accent);
  }
  .muted {
    background: transparent;
    border: 1px dashed var(--line-2);
    color: var(--ink-3);
  }
</style>
