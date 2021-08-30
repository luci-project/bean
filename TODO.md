TODO
----

 * Improve relocation handling (size and resolving), so there are now security issues and no need for `-r` flag. Especially focus on:
   * `R_X86_64_COPY`
   * `R_X86_64_IRELATIVE`
   * TLS relocs
 * Check/improve TLS handling
 * ...
