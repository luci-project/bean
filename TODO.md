TODO
----

 * Two Modes:
   1. Update possible without modification of .data/.bss?
   2. Update with fixing relocations in .data/.bss (`-r` flag?)
 * Improve relocation handling (size and resolving), so there are now security issues and no need for `-r` flag. Especially focus on:
   * `R_X86_64_COPY`
   * `R_X86_64_IRELATIVE`
   * TLS relocs
 * Check/improve TLS handling
 * ...
