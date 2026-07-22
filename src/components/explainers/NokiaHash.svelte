<script lang="ts">
  import { link } from "../../lib/router";
</script>

<p class="lede">
  <span class="mono">hash</span> (no digit) is the original SR OS format for storing reversible
  config secrets, predating <span class="mono">hash2</span>, <span class="mono">custom</span> and
  <span class="mono">hash3</span>. It is the <strong>same construction as hash2 with the salt
  removed</strong>. We document it rather than decode it: reversing it needs the fixed key embedded
  in SR OS, which we deliberately do not publish.
</p>

<div class="callout">
  <p class="callout-title mono">Why there is no decoder here</p>
  <p>
    <span class="mono">hash</span> is reversible with the <strong>same fixed key compiled into
    SR OS</strong> as <span class="mono">hash2</span>. Worse, because it carries <strong>no
    salt</strong>, a single copy of that key decodes <em>any</em> <span class="mono">hash</span>
    value from any device, with no config context at all. I have recovered the key, but hosting a
    decoder would publish it, and I would rather keep it off the public internet. If you own the
    device and need a secret back, re-store that value as
    <a href="/nokia-custom-hash" use:link>custom-hash</a> (your own key) instead.
  </p>
</div>

<h2>How it works</h2>
<p>
  For each secret, <span class="mono">hash</span> builds a 16-byte tag from the plaintext and runs a
  fixed-key AES-256-CTR stream over it - no salt in sight:
</p>

<ol class="steps">
  <li>
    <span class="step-k mono">1 · tag</span>
    <span class="step-v">
      <span class="mono">V = SHA-256(plaintext)[:16]</span> - an integrity tag stored in the clear
      as the first 16 bytes of every value. It depends only on the plaintext, so it is the same
      everywhere for the same secret.
    </span>
  </li>
  <li>
    <span class="step-k mono">2 · stream</span>
    <span class="step-v">
      <span class="mono">keystream = AES-256-CTR(K, IV = V)</span>, where <span class="mono">K</span>
      is the fixed key embedded in SR OS. This is the one difference from
      <span class="mono">hash2</span>, which uses <span class="mono">IV = V XOR salt</span>.
    </span>
  </li>
  <li>
    <span class="step-k mono">3 · emit</span>
    <span class="step-v">
      <span class="mono">value = base64( V || (plaintext XOR keystream) )</span>, written as
      <code>&lt;base64&gt; hash</code>. Ciphertext length = plaintext length + 16.
    </span>
  </li>
</ol>

<p class="fineprint">
  Example (isis <span class="mono">hello-authentication-key</span>): the plaintext
  <span class="mono">HelloWorld123</span> stores as
  <span class="mono">qzHIhn90lA+IOkm+pgQy3VFpJUHJrpKZScNQThY= hash</span>. It is legacy and not the
  default - SR OS defaults to <span class="mono">hash2</span>; you only see
  <span class="mono">hash</span> if an interface's algorithm is explicitly set to it.
</p>

<h2>Does no salt weaken the key?</h2>
<p>
  No. A known (plaintext, value) pair only reveals one AES <strong>known-plaintext pair</strong>:
  the first keystream block equals <span class="mono">E_K(V)</span>, with <span class="mono">V</span>
  public. AES-256 is built to resist key recovery from such pairs, so the master key stays as hard
  to find as with <span class="mono">hash2</span> - it has to be extracted from the firmware either
  way. What the missing salt <em>does</em> make easier is everything downstream: any value decodes
  with no context once the key is known, and identical secrets collide to identical values. The salt
  buys context-binding, not key secrecy.
</p>

<h2>Security takeaways</h2>
<ul class="takeaways">
  <li>
    <span class="mono">hash</span> is the <strong>weakest of the four</strong> Nokia formats:
    unsalted, so one key decodes every value everywhere, with no leaf, seed or path needed.
  </li>
  <li>
    The tag <span class="mono">V = SHA-256(plaintext)[:16]</span> is <strong>in the clear</strong>
    and unsalted, so identical secrets are visible as identical values (reuse fingerprinting) and
    weak secrets fall to an offline dictionary attack over <span class="mono">V</span> alone - no key
    needed.
  </li>
  <li>
    It is legacy; don't choose it. Use <span class="mono">custom</span> (your own AES key) or
    <span class="mono">hash3</span> (a user primary secret), and treat any stored config as sensitive
    regardless.
  </li>
</ul>
