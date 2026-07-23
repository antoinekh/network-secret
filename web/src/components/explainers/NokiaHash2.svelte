<script lang="ts">
  import { link } from "../../lib/router";
</script>

<p class="lede">
  <span class="mono">hash2</span> is the SR OS default for storing reversible secrets in a
  configuration, alongside <span class="mono">hash</span>, <span class="mono">custom</span> and
  (from 26.7) <span class="mono">hash3</span>. Despite the name it is <strong>not a hash</strong>: it
  is reversible obfuscation. We document it here rather than decoding it, because reversing it
  requires a key that is embedded in the SR OS software - publishing a live decoder would mean
  publishing that key.
</p>

<div class="callout">
  <p class="callout-title mono">Why there is no decoder here</p>
  <p>
    hash2 is reversible with a <strong>single fixed key that is compiled into SR OS</strong> - the
    same on every box of a release, recoverable only by pulling it out of the firmware. A hash2
    decoder is really just that key plus a few lines of AES. We deliberately do not host it: putting
    the master key on the public internet would let anyone decode <span class="mono">hash2</span>
    secrets from any leaked or shared SR OS config. If you own the device and need a secret back,
    switch that value to <a href="/nokia-custom-hash" use:link>custom-hash</a> instead.
  </p>
</div>

<h2>Leaf-specific</h2>
<p>
  hash2 is <strong>leaf-specific</strong>: the key is a fixed global constant, so the same plaintext
  in the same configuration location renders <strong>identically on any router</strong>. What
  changes the output is the <strong>per-leaf-key salt</strong>; the same secret at a different
  config location encodes differently. Stored values still diverge between nodes in practice, but
  only because the same logical key sits at different paths (interface names differ, for instance),
  giving different salts. The portable <span class="mono">custom</span> and
  <span class="mono">hash3</span> formats exist to remove the config-diff and copy-paste pain this
  causes.
</p>

<h2>How it works</h2>
<p>
  For each secret, hash2 builds a 16-byte tag from the plaintext, derives a per-location salt, and
  runs a fixed-key AES-256-CTR stream over the plaintext:
</p>

<ol class="steps">
  <li>
    <span class="step-k mono">1 · tag</span>
    <span class="step-v">
      <span class="mono">V = SHA-256(plaintext)[:16]</span> - an integrity tag stored in the clear
      as the first 16 bytes of every value. It depends only on the plaintext, so it is the
      <em>same everywhere</em> for the same secret.
    </span>
  </li>
  <li>
    <span class="step-k mono">2 · salt</span>
    <span class="step-v">
      <span class="mono">salt = SHA-256(per-leaf seed + config path keys)[:16]</span> - a
      per-configuration-leaf-key value. Each encrypted leaf has its own 16-char seed; this is what
      makes hash2 location-specific.
    </span>
  </li>
  <li>
    <span class="step-k mono">3 · stream</span>
    <span class="step-v">
      <span class="mono">keystream = AES-256-CTR(K, IV = V XOR salt)</span>, where
      <span class="mono">K</span> is the fixed key embedded in SR OS.
    </span>
  </li>
  <li>
    <span class="step-k mono">4 · emit</span>
    <span class="step-v">
      <span class="mono">value = base64( V || (plaintext XOR keystream) )</span>, written as
      <code>&lt;base64&gt; hash2</code>. Ciphertext length = plaintext length + 16.
    </span>
  </li>
</ol>

<p class="fineprint">
  The older <span class="mono">hash</span> format (no digit) is this same construction with step 2
  removed - <span class="mono">IV = V</span>, no salt - so it is even weaker. See
  <a href="/hash" use:link>Nokia hash</a>.
</p>

<h2>Security takeaways</h2>
<ul class="takeaways">
  <li>
    hash2 is <strong>obfuscation, not encryption</strong>, but the global key is not public, so it
    still offers real protection: a hash2 value stays safe as long as that embedded key (and the
    per-leaf salt derivation) are kept off the internet. That is exactly why we do not host a decoder
    or publish the key here.
  </li>
  <li>
    The tag <span class="mono">V = SHA-256(plaintext)[:16]</span> sits <strong>in the clear</strong>
    and is unsalted, so identical secrets are visible as identical tags (password-reuse
    fingerprinting), and weak secrets fall to an offline dictionary attack over
    <span class="mono">V</span> alone - no key needed.
  </li>
  <li>
    For anything you actually want to protect, don't rely on hash2. Use
    <span class="mono">custom</span> (your own AES key) or <span class="mono">hash3</span> (a user
    primary secret), and treat any stored config as sensitive regardless.
  </li>
</ul>
