FROM clamav/clamav:1.3
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
