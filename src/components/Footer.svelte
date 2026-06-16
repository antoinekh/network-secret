<script lang="ts">
  const year = new Date().getFullYear();
</script>

<footer class="ftr">
  <div class="wrap row">
    <span class="mono note">
      All computation runs in your browser. No value is ever sent to a server.
    </span>
    <span class="right">
      <a
        class="mono contact"
        href="https://github.com/antoinekh"
        target="_blank"
        rel="noopener noreferrer">Contact ↗</a
      >
      <span class="mono dim">© {year} · static site</span>
    </span>
  </div>
</footer>

<style>
  .ftr {
    border-top: 1px solid var(--line);
    margin-top: clamp(1.2rem, 3vw, 2.2rem);
  }
  .row {
    display: flex;
    align-items: baseline;
    justify-content: space-between;
    gap: 1rem;
    flex-wrap: wrap;
    padding-block: 1rem 1.2rem;
  }
  .note {
    font-size: 0.72rem;
    color: var(--ink-2);
  }
  .right {
    display: flex;
    align-items: baseline;
    gap: 1.1rem;
  }
  .contact {
    font-size: 0.72rem;
    color: var(--ink-2);
    transition: color 0.15s ease;
  }
  .contact:hover {
    color: var(--accent);
  }
  .dim {
    font-size: 0.68rem;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    color: var(--ink-3);
  }
</style>
