<script lang="ts">
  const year = new Date().getFullYear();
</script>

<footer class="ftr">
  <div class="wrap row">
    <span class="mono note">
      All computation runs in your browser. No value is ever sent to a server.
    </span>
    <span class="mono dim">© {year} · static site</span>
  </div>
</footer>

<style>
  .ftr {
    border-top: 1px solid var(--line);
    margin-top: clamp(3rem, 8vw, 6rem);
  }
  .row {
    display: flex;
    align-items: baseline;
    justify-content: space-between;
    gap: 1rem;
    flex-wrap: wrap;
    padding-block: 1.5rem 2rem;
  }
  .note {
    font-size: 0.72rem;
    color: var(--ink-2);
  }
  .dim {
    font-size: 0.68rem;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    color: var(--ink-3);
  }
</style>
