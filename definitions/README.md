# Hush definitions catalog

These files are the seed/fixture catalog for the Hush code repository. The live public catalog
is published separately at `bardagi/hush-definitions` so policy changes can ship independently
of the Hush binaries.

The live repository should keep this layout:

```text
definitions/
  manifest.json
  manifest.json.sig
  *.json
  .gitattributes
```

Edit only the individual definition JSON files. On the offline signing machine, regenerate the
manifest and detached signature with:

```powershell
..\tools\Protect-HushManifest.ps1 `
  -DefinitionsDir .\definitions `
  -PrivateKeyPath .\hush-private.xml.dpapi
```

The Hush client trusts the pinned public key and the signed manifest, not the Git repository or
HTTPS transport. Never commit a private key or publish an unsigned catalog commit.
