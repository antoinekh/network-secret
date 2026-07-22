<script lang="ts">
  import { link } from "../../lib/router";
</script>

<p class="lede">
  SR OS 26.7 adds a fourth way to store reversible secrets in a configuration, tagged
  <span class="mono">hash3</span>, alongside <span class="mono">hash</span>,
  <span class="mono">hash2</span> and <span class="mono">custom</span> - all four are reversible
  protection, none is a one-way password hash. Unlike the others, hash3 is a genuine authenticated
  cipher keyed to a <strong>user-configurable primary secret</strong>. This page documents it rather
  than decoding it: reproducing a hash3 value offline needs key material lifted out of the SR OS
  binary, plus the per-config-leaf salt - so it is an explainer, not a converter.
</p>

<div class="callout">
  <p class="callout-title mono">Why there is no decoder here</p>
  <p>
    Two reasons. First, the master secret that ultimately keys every value lives in the router's
    protected key store (persisted, encrypted, in the per-system file
    <span class="mono">cf3:\encrypted-secrets.dat</span>, whose own header reads: <em>“This file is
    specific to a single system. It is not portable.”</em>). Recovering it means extracting key
    material from the SR OS software itself - the same class of work as the global keys behind
    <span class="mono">hash2</span>, which we deliberately do not publish. Second, the per-value key
    is <strong>salted per configuration leaf-key</strong>: the salt is derived from where the secret
    sits in the config, so even with the master secret you also need the exact config context. A
    browser page cannot reproduce either input.
  </p>
</div>

<h2>What it protects</h2>
<p>
  hash3 is selected per management interface, exactly like <span class="mono">custom</span> in the
  consistent-hashing model: <span class="mono">classic-cli</span>, <span class="mono">md-cli</span>,
  <span class="mono">netconf</span> and <span class="mono">grpc</span> each render stored secrets
  with their own <span class="mono">hash-algorithm</span>. Once a primary secret is commissioned,
  hash3 becomes the default for securing reversible shared secrets (authentication keys, community
  strings, pre-shared keys, and so on).
</p>

<h2>How it works</h2>
<p>
  Commissioning a primary secret gives the router a master secret it keeps in its key store. Every
  stored value is then sealed with a key derived from that master secret and a per-location salt:
</p>

<ol class="steps">
  <li>
    <span class="step-k mono">1 · salt</span>
    <span class="step-v">
      A 16-byte salt is derived from <em>where</em> the secret lives in the config -
      <span class="mono">SHA-256(per-leaf seed + the config path keys)</span>, the same per-leaf-key
      scheme as <span class="mono">hash2</span>. Two identical secrets in different places get
      different salts.
    </span>
  </li>
  <li>
    <span class="step-k mono">2 · derive</span>
    <span class="step-v">
      A per-value AES key is derived with
      <span class="mono">PBKDF2-HMAC-SHA3-512(master, salt, 10 iterations)</span>, taking the first
      32 bytes as an AES-256 key.
    </span>
  </li>
  <li>
    <span class="step-k mono">3 · encrypt</span>
    <span class="step-v">
      The secret is sealed with <strong>AES-256-GCM</strong> (a 12-byte nonce, a 16-byte
      authentication tag); the parameter block is wrapped with an AES-128-CTR pass. The result is
      base64-encoded and tagged <span class="mono">hash3</span> in the config.
    </span>
  </li>
</ol>
<p class="fineprint">
  The salt being per-configuration-leaf-key is why a hash3 value is tied to its exact spot in the
  config: to derive the key you need the master secret <em>and</em> the leaf's seed and path keys.
</p>

<h2>The wire format</h2>
<p>
  A hash3 value is <code>&lt;base64&gt; hash3</code>. Decoded, the envelope is a fixed 56-byte
  overhead around the ciphertext (which is the same length as the plaintext), fully diffused so no
  field is readable without the key:
</p>

<pre class="diagram mono">[ 0 :  4]  header      version + parameters
[ 4 : 24]  params      AES-128-CTR( iteration count + params )
[24 : 40]  nonce       AES-256-GCM IV = nonce[:12]
[40 : 40+n] ciphertext AES-256-GCM( secret )     (n = plaintext length)
[.. : end]  tag        AES-256-GCM auth tag (16 bytes)

the per-leaf salt is NOT stored here; it is re-derived
from the config path, so decoding also needs the context</pre>

<p class="fineprint">
  Verified against SR OS 26.7: encryption is deterministic for a given (master secret, config
  context), so the same secret in the same place always renders identically, and flipping one input
  byte changes every output byte. The construction is <span class="mono">PBKDF2-HMAC-SHA3-512</span>
  + <span class="mono">AES-256-GCM</span>.
</p>

<h2>What it takes to decode one</h2>
<p>Two things are worth spelling out:</p>
<ul class="takeaways">
  <li>
    <strong>The salt is not per-device.</strong> It is
    <span class="mono">SHA-256(global per-leaf seed + config path keys)[:16]</span> - the seed is a
    constant baked into SR OS, the path keys are config values (router, interface, level). The same
    config location yields the same salt on any router of that release; it binds a value to its
    <em>place in the config</em>, not to the box.
  </li>
  <li>
    <strong><span class="mono">encrypted-secrets.dat</span> is not enough on its own.</strong> It
    holds the master material encrypted under a <strong>system-bound key</strong> - that is what
    "specific to a single system, not portable" means. Unlocking it needs the router's own
    keystore/EEPROM key material (derived at boot), not something reproducible from the file alone.
  </li>
</ul>
<p>
  So the full recipe is:
  <span class="mono">encrypted-secrets.dat + that system's unlock key → master material</span>, then
  <span class="mono">master material + per-leaf salt + the value → plaintext</span>. The system-bound
  unlock is the crux, and it is why hash3 is genuinely non-portable in a way
  <span class="mono">hash</span>/<span class="mono">hash2</span> are not.
</p>

<h2>Setting it up</h2>
<p>On the router, commission a primary secret, then switch the interfaces to hash3:</p>
<pre class="code mono">{`# commission the primary secret (prompts twice, then saves config)
admin system security storage-encryption primary-secret set-secret

# render secrets as hash3 on the interfaces you read from
configure private
system security hash-control management-interface md-cli hash-algorithm hash3
system security hash-control management-interface netconf hash-algorithm hash3
commit`}</pre>
<p class="fineprint">
  Back up <span class="mono">encrypted-secrets.dat</span>: without it, a replacement chassis cannot
  decode a saved config that contains hash3 values, even with the right primary secret.
</p>

<h2>Security takeaways</h2>
<ul class="takeaways">
  <li>
    hash3 is <strong>reversible protection, not a one-way hash</strong> - like
    <span class="mono">hash</span>, <span class="mono">hash2</span> and
    <span class="mono">custom</span>. But recovering the plaintext needs <strong>more than the
    master secret</strong>: you also need the per-leaf salt, i.e. the leaf's seed plus its exact
    config path. Master secret alone is not enough.
  </li>
  <li>
    It is a genuine <strong>AEAD</strong> (AES-256-GCM with SHA3-512 key derivation), a real step up
    from <span class="mono">hash2</span>/<span class="mono">custom</span>, which are trivially
    reversible obfuscation.
  </li>
  <li>
    The master secret lives in the router's key store and is bound to the system via
    <span class="mono">encrypted-secrets.dat</span>; combined with the per-leaf-key salt, that makes
    hash3 values effectively <strong>non-portable</strong>. Treat the primary secret and that file
    as the crown jewels.
  </li>
</ul>
