---
title: Verifying
weight: 120
description: >
  Verify Inspektor Gadget
---

Inspektor Gadget container image and release assets are signed using
[`cosign`](https://github.com/sigstore/cosign).
In this guide, we will see how you can verify them with this tool.
Note that, You would need to have `cosign` [v2.0](https://github.com/sigstore/cosign/blob/main/README.md#developer-installation) installed.

## Verify the container image manually

Verifying the container image is pretty straightforward:

```bash
$ RELEASE='v0.27.0'
$ cosign verify --key https://raw.githubusercontent.com/inspektor-gadget/inspektor-gadget/${RELEASE}/inspektor-gadget.pub ghcr.io/inspektor-gadget/inspektor-gadget:${RELEASE}
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - Existence of the claims in the transparency log was verified offline
  - The signatures were verified against the specified public key

[{"critical":{"identity":{"docker-reference":"ghcr.io/inspektor-gadget/inspektor-gadget"}, ...
]
```

Getting the above output followed by a JSON array of payloads, ensures you the
container image was signed using our private key.

## Verify the container image while deploying

When deploying Inspektor Gadget using `kubectl gadget deploy`, the image will be automatically verified if the `policy-controller` is deployed on your Kubernetes cluster.
To do so, you first need to [install](https://docs.sigstore.dev/policy-controller/installation/) this component.
Now, let's deploy Inspektor Gadget in a cluster where the `policy-controller` is present:

```bash
$ kubectl get pod -n cosign-system
NAME                                         READY   STATUS    RESTARTS   AGE
policy-controller-webhook-7c7f55dfcf-qkpw4   1/1     Running   0          10s
$ kubectl gadget deploy
...
1/1 gadget pod(s) ready
...
Inspektor Gadget successfully deployed
```

As you can see, everything was successfully deployed.
Now, let's undeploy Inspektor Gadget and try to deploy an old release which was not signed:

```bash
$ kubectl gadget undeploy
...
Inspektor Gadget successfully removed
$ kubectl gadget deploy --image 'ghcr.io/inspektor-gadget/inspektor-gadget:v0.22.0'
...
Creating DaemonSet/gadget...
Error: problem while creating resource: creating "DaemonSet": admission webhook "policy.sigstore.dev" denied the request: validation failed: failed policy: gadget-image-policy: spec.template.spec.containers[0].image
ghcr.io/inspektor-gadget/inspektor-gadget@sha256:9272c2be979a9857971fc8b6f7226e609cadec8352f97e9769081930121ef27f signature key validation failed for authority authority-0 for ghcr.io/inspektor-gadget/inspektor-gadget@sha256:9272c2be979a9857971fc8b6f7226e609cadec8352f97e9769081930121ef27f: no matching signatures
```

As this image is not signed, the verification failed and the container was not deployed to the cluster.

In case the `policy-controller` is not present, a warning message will be printed to inform you the verification will not take place:

```bash
$ kubectl get pod -n cosign-system
No resources found in cosign-system namespace.
$ kubectl gadget deploy
WARN[0000] No policy controller found, the container image will not be verified
...
Inspektor Gadget successfully deployed
```

### Skipping verification

You can also decide to not verify the image, using `--verify-image=false`.
We definitely do not recommend this and you will use this option at your own risk:

```bash
$ kubectl gadget deploy --verify-image=false
WARN[0000] You used --verify-image=false, the container image will not be verified
...
Inspektor Gadget successfully deployed
```

### Using custom public key for verification

To verify the image with a specific key, you can use the `--public-key` flag:

```bash
$ kubectl gadget deploy --public-key="$(cat pkg/resources/inspektor-gadget.pub)"
```

## Verify the container Source Code Bill Of Materials (SBOMs)

A Software Bill of Materials (SBOM) is a detailed list of all the components of a software.
It facilitates security and license compliance assessments.
The Inspektor Gadget project publishes SBOMs in the [CycloneDX format](https://cyclonedx.org/specification/overview/) for all our container images and CLI tools:
* SBOMs for container images are attached to the corresponding image and can be found in our [registry](https://github.com/orgs/inspektor-gadget/packages).
* SBOMs for CLI tools are available as [release](https://github.com/inspektor-gadget/inspektor-gadget/releases) assets.

In this section, we will see how you can verify and inspect the SBOMs attached to our container images.
To do so, you will need `cosign`, [`oras`](https://oras.land/docs/installation) and Inspektor Gadget public key.

```bash
# We will demo this for amd64, but it works the same for arm64.
$ arch=amd64
$ oras discover --platform linux/${arch} --artifact-type example/sbom ghcr.io/inspektor-gadget/inspektor-gadget:latest
Discovered 1 artifact referencing latest
Digest: sha256:...

Artifact Type   Digest
example/sbom    sha256:hash_of_sbom_manifest
# As we include SBOMs in our multi architecture container image, they are also
# signed.
# So, let's check the SBOM is signed with our private key:
$ cosign verify --key inspektor-gadget.pub ghcr.io/inspektor-gadget/inspektor-gadget@sha256:hash_of_sbom_manifest

Verification for ghcr.io/inspektor-gadget/inspektor-gadget@sha256:hash_of_sbom_manifest
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - Existence of the claims in the transparency log was verified offline
  - The signatures were verified against the specified public key

[{"critical":{"identity":{"docker-reference":"ghcr.io/inspektor-gadget/inspektor-gadget"}, ...
]
# Let's download the SBOM and look at it:
$ oras pull --allow-path-traversal ghcr.io/inspektor-gadget/inspektor-gadget@sha256:hash_of_sbom_manifest
Downloading 1d479bb51392 /tmp/gadget-container-image-linux-amd64/sbom_cyclonedx.json
Downloaded  1d479bb51392 /tmp/gadget-container-image-linux-amd64/sbom_cyclonedx.json
Pulled [registry] ghcr.io/eiffel-fl/inspektor-gadget@sha256:hash_of_sbom_manifest
Digest: sha256:hash_of_sbom_manifest
$ jq '' /tmp/gadget-container-image-linux-amd64/sbom_cyclonedx.json
{
  "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:cf132c3d-5960-4536-9c03-9724babd76e9",
  "version": 1,
  "metadata": {
    "timestamp": "2024-03-21T17:22:38Z",
    "tools": {
      "components": [
        {
          "type": "application",
          "author": "anchore",
          "name": "syft",
          "version": "1.0.1"
        }
      ]
    },
    "component": {
      "bom-ref": "af63bd4c8601b7f1",
      "type": "file",
      "name": "."
    }
  },
  "components": [
    {
      "bom-ref": "pkg:deb/debian/base-files@12.4+deb12u5?arch=amd64&distro=debian-12&package-id=854ccee33785ad46",
      "type": "library",
      "publisher": "Santiago Vila <sanvila@debian.org>",
      "name": "base-files",
...
}
```

As the SBOM was signed with our private key, you can now inspect it to track down every dependencies we use to build our container image.

## Verify image-based gadgets

Like our container image, we sign all our image-based gadgets.
The signature are verified by default using Inspektor Gadget public key:

```bash
$ sudo -E ig run ghcr.io/inspektor-gadget/gadget/trace_open:latest
RUNTIME.CONTAINERNA… PID         UID         GID         MNTNS_ID E… FD         FL… MODE       COMM       FNAME                TIMESTAMP
```

Let's try to run an image-based gadget which was not signed:

```bash
$ sudo -E ig run ghcr.io/inspektor-gadget/gadget/trace_open:v0.27.0
Error: fetching gadget information: initializing and preparing operators: instantiating operator "oci": ensuring image: verifying image "ghcr.io/inspektor-gadget/gadget/trace_open:v0.27.0": getting signing information: getting signature: getting signature bytes: ghcr.io/inspektor-gadget/gadget/trace_open:sha256-0c0e2fa72ae70e65351ab7a48a1cd5a68752a94d9c36e7b51e8764a1b7be3d7a.sig: not found
```

As the image was not signed, no signature was found in the repository, so the execution is denied.

You can set your own public key with `--public-key`:

```bash
$ sudo -E ig run --public-key="$(cat your-key.pub)" ghcr.io/your-repo/gadget/trace_open
RUNTIME.CONTAINERNAME  PID          UID          GID          MNTNS_ID RET FL… MODE        COMM        FNAME                  TIMESTAMP
```

If you forget to set your public key, the image-based gadget will be verified using Inspektor Gadget public key and you will get the following error:

```bash
$ sudo -E ig run ghcr.io/your-repo/gadget/trace_open
Error: fetching gadget information: initializing and preparing operators: instantiating operator "oci": ensuring image: verifying image "ghcr.io/your-repo/gadget/trace_open": verifying signature: invalid signature when validating ASN.1 encoded signature
```

You can also skip verifying image-based gadget signature with `--verify-image=false`.
Note that we do not recommend using this:

```bash
$ sudo -E ig run --verify-image=false ghcr.io/your-repo/gadget/trace_open
WARN[0000] you set --verify-image=false, image will not be verified
WARN[0000] you set --verify-image=false, image will not be verified
RUNTIME.CONTAINERNAME  PID          UID          GID          MNTNS_ID RET FL… MODE        COMM        FNAME                  TIMESTAMP
```

## Verify the ebpf-builder image

We also sign the `ebpf-builder` image which is used to build gadgets.
You can verify it using the following:

```bash
$ cosign verify --key inspektor-gadget.pub ghcr.io/inspektor-gadget/ebpf-builder:latest
```

We highly recommend you to verify by digest and specify the digest when building:

```bash
$ DIGEST='sha256:4967ad1a11a9ed32867dc0d63e137dc2196c560db4b3644c7c0c97fccea7c522'
$ cosign verify --key inspektor-gadget.pub ghcr.io/inspektor-gadget/ebpf-builder@$DIGEST

Verification for ghcr.io/inspektor-gadget/ebpf-builder@sha256:4967ad1a11a9ed32867dc0d63e137dc2196c560db4b3644c7c0c97fccea7c522 --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - Existence of the claims in the transparency log was verified offline
  - The signatures were verified against the specified public key

[{"critical":{"identity":{"docker-reference":"ghcr.io/inspektor-gadget/ebpf-builder"}, ...
]
$ sudo -E ig image build -t trace_exec:build-verified -f gadgets/trace_exec/gadget.yaml --builder-image ghcr.io/inspektor-gadget/ebpf-builder@$DIGEST gadgets/trace_exec
INFO[0000] Experimental features enabled
Pulling builder image ghcr.io/inspektor-gadget/ebpf-builder@sha256:4967ad1a11a9ed32867dc0d63e137dc2196c560db4b3644c7c0c97fccea7c522
ghcr.io/inspektor-gadget/ebpf-builder@sha256:4967ad1a11a9ed32867dc0d63e137dc2196c560db4b3644c7c0c97fccea7c522: Pulling from inspektor-gadget/ebpf-builder
...
Digest: sha256:4967ad1a11a9ed32867dc0d63e137dc2196c560db4b3644c7c0c97fccea7c522
Status: Downloaded newer image for ghcr.io/inspektor-gadget/ebpf-builder@sha256:4967ad1a11a9ed32867dc0d63e137dc2196c560db4b3644c7c0c97fccea7c522
Successfully built ghcr.io/inspektor-gadget/gadget/trace_exec:build-verified@sha256:c85eac1e4615a08c74883402f73c5f8667b64597bd51f9e46275dfdbb0a04703
```

## Verify an asset

Rather than signing all the assets, we only sign the checksums file.
So, by verifying this file, you can then verify the assets themselves by
checking their checksums.

## Verifying the checksums file

The following snippet show you how to verify the checksums file:

```bash
$ RELEASE='v0.19.0'
$ ASSET="SHA256SUMS"
$ URL="https://github.com/inspektor-gadget/inspektor-gadget/releases/download/${RELEASE}"
# We need to get the asset itself, its signature file and the corresponding bundle:
$ for i in $URL/$ASSET $URL/$ASSET.sig $URL/$ASSET.bundle; do
	wget $i
done
...
# We need to get the public key too.
$ wget $URL/inspektor-gadget.pub
...
$ cosign verify-blob $ASSET --bundle ${ASSET}.bundle --signature ${ASSET}.sig --key inspektor-gadget.pub --offline
Verified OK
```

As you can see, the checksum file was correctly verified which means this file was indeed signed by us.
So, you can use this file to verify other release assets.

## Verify an asset

Once you verified the checksums file, you can now verify the integrity of an asset using such checksums file:

```bash
$ RELEASE='v0.19.0'
$ ASSET="inspektor-gadget-${RELEASE}.yaml"
$ URL="https://github.com/inspektor-gadget/inspektor-gadget/releases/download/${RELEASE}"
$ wget $URL/$ASSET
$ grep $ASSET SHA256SUMS | shasum -a 256 -c -s || echo "Error: ${ASSET} didn't pass the checksum verification. You must not use it!"
```
