# clamav/clamav:1.3 does not exist -- an earlier version of this
# Dockerfile guessed at a version number with no way to check it against
# a real registry (this environment has no Docker/network access), and
# "docker compose up" failed outright with "not found" the first time
# this was actually run. Confirmed against the official docs
# (docs.clamav.net/manual/Installing/Docker.html): valid tags are
# clamav/clamav:<MAJOR.MINOR[.PATCH]>[_base], :stable[_base],
# :unstable[_base], :latest[_base]. "stable" is used here because it
# comes preloaded with signature databases (the non-_base form), which
# suits a one-shot test container better than the _base variant, which
# needs a persistent volume and downloads the full set from scratch
# every time.
FROM clamav/clamav:stable
# Base image runs freshclam (signature updates from ClamAV's official
# mirror network -- the externally governed source under test) and clamd
# on startup via its own entrypoint. /scan and /quarantine are created
# here so ownership/permissions are predictable for the ablation.
RUN mkdir -p /scan /quarantine && chown clamav:clamav /scan /quarantine

# The EICAR test string is generated INSIDE the image at build time,
# never as a file in the git working tree. It is a standardised,
# harmless test string every antivirus engine (including Windows
# Defender and ClamAV itself) is designed to flag -- which is exactly
# what makes it useless as a repo artefact: any host-side antivirus
# scanning the working tree, or a plain `Get-FileHash`/`git add` pass on
# Windows, will refuse to read a file containing it. Kept as
# /scan/eicar-source.txt (a template the entrypoint copies from, never
# scanned itself) rather than /scan/eicar.txt, so a stray early scan of
# the whole /scan directory during container startup doesn't quarantine
# the only copy before the test gets to use it.
RUN printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /scan/eicar-source.txt \
 && chown clamav:clamav /scan/eicar-source.txt
