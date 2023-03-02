---
title: Verifying
weight: 100
description: >
  Verify Inspektor Gadget release assets
---

The Inspektor Gadget release assets are signed using [`cosign`]().
In this guide, we will see how you can verify release assets with this tool

## Verifying release assets

You would need to have `cosign` 2.0 installed to verify the release assets:

```bash
$ RELEASE='v0.14.0'
$ ASSET="inspektor-gadget-${RELEASE}.yaml"
$ URL="https://github.com/inspektor-gadget/inspektor-gadget/releases/download/${RELEASE}"
# We need to get the asset itself, its signature file and the corresponding certificate:
$ for i in $URL/$ASSET $URL/$ASSET.sig $URL/$ASSET.cert; do
	wget $i
done
...
$ cat ${ASSET}.cert | base64 -d | openssl x509 -text -noout
...
            X509v3 Subject Alternative Name: critical
                URI:https://github.com/inspektor-gadget/inspektor-gadget/.github/workflows/inspektor-gadget.yml@refs/tags/v0.14.0
            1.3.6.1.4.1.57264.1.1:
                https://token.actions.githubusercontent.com
...
$ cosign verify-blob $ASSET --certificate ${ASSET}.cert --signature ${ASSET}.sig --certificate-identity https://github.com/inspektor-gadget/inspektor-gadget/.github/workflows/inspektor-gadget.yml@refs/tags/v0.14.0 --certificate-oidc-issuer https://token.actions.githubusercontent.com
Verified OK
```

As you can see, the release asset was correctly verified which means this file was indeed signed by us.
So, you can use this release asset without worrying about his authenticity.
Note that, you would need to have an internet connection for `cosign` to verify the release asset.
