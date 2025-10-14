This directory holds the public portion of actual production
certificates.  They are expected to be updated very rarely, because
revoking or replacing one has large downstream effects on production
servers, fielded clients, and/or exemptions certifications held by
synthesis customers or biosafety authorities.  Because of this, no
private keys nor passphrases may be checked into this directory.
In addition, root certs and certs near the roots are never kept online
anywhere and are never handled on non-airgapped hardware.  Note that
everything in this directory must be public, since verifying a
certificate chain involves verifying all certs back to the roots.

Note that verifiable screening certificates are not held here,
because they are frequently rotated.  For those, look in the
[Verifiable screening](https://github.com/SecureDNA/verifiable-screening)
repository.
