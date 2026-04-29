# Node.js Bindings for rust-oci-client

Node.js bindings for the [rust-oci-client](https://github.com/oras-project/rust-oci-client) library, providing high-performance OCI Distribution client functionality.

**Version**: These bindings are versioned in sync with the parent `oci-client` crate.

## Features

- **Pure API Mirror**: Function signatures match the native Rust functions exactly
- **High Performance**: Uses NAPI-RS for zero-copy data transfer where possible
- **Full Auth Support**: Anonymous, Basic (username/password), and Bearer token authentication
- **Complete ClientConfig**: All native configuration options exposed
- **TypeScript Support**: Full type definitions included

## Installation

```bash
npm install @oras-project/oci-client
# or
yarn add @oras-project/oci-client
```

## Usage

```typescript
import { OciClient, ClientProtocol, anonymousAuth, basicAuth } from '@oras-project/oci-client';

// Create a client with default configuration
const client = new OciClient();

// Or with custom configuration
const clientWithConfig = OciClient.withConfig({
  protocol: ClientProtocol.Https,
  acceptInvalidCertificates: false,
  maxConcurrentDownload: 8,
  maxConcurrentUpload: 8,
});

// Create a client targeting a specific platform (for multi-arch images)
const armClient = OciClient.withConfig({
  platform: {
    os: 'linux',
    architecture: 'arm64',
    variant: 'v8'  // optional
  }
});

// Pull an image
const imageData = await client.pull(
  'ghcr.io/example/image:latest',
  anonymousAuth(),
  ['application/vnd.oci.image.layer.v1.tar+gzip']
);

console.log(`Pulled ${imageData.layers.length} layers`);
console.log(`Digest: ${imageData.digest}`);

// Push an image
const response = await client.push(
  'registry.example.com/myimage:v1',
  layers,
  config,
  basicAuth('username', 'password'),
  null // Let the client generate the manifest
);

console.log(`Manifest URL: ${response.manifestUrl}`);

// Pull image manifest
const { manifest, digest } = await client.pullImageManifest(
  'ghcr.io/example/image:latest',
  anonymousAuth()
);

// Push a manifest list (multi-platform image)
const manifestUrl = await client.pushManifestList(
  'registry.example.com/myimage:v1',
  basicAuth('username', 'password'),
  imageIndex
);

// Pull referrers (OCI 1.1)
const referrers = await client.pullReferrers(
  'ghcr.io/example/image@sha256:abc123...',
  'application/vnd.example.sbom'
);
```

## API Reference

### Client

#### `new OciClient()`
Create a client with default configuration.

#### `OciClient.withConfig(config: ClientConfig)`
Create a client with custom configuration.

### Platform Selection

For multi-platform images (Image Index/Manifest List), you can specify the target platform:

```typescript
const client = OciClient.withConfig({
  platform: {
    os: 'linux',           // Required: linux, windows, darwin, etc.
    architecture: 'arm64', // Required: amd64, arm64, arm, etc.
    variant: 'v8'          // Optional: v7, v8, etc. for ARM
  }
});
```

When pulling an image that references an Image Index, the client will automatically select the manifest matching the specified platform.

### Authentication

#### `anonymousAuth()`
Create anonymous authentication.

#### `basicAuth(username: string, password: string)`
Create HTTP Basic authentication.

#### `bearerAuth(token: string)`
Create Bearer token authentication.

### Main Functions

#### `pull(image, auth, acceptedMediaTypes)`
Pull an image from the registry. Returns `ImageData` with layers as Buffers.

#### `push(imageRef, layers, config, auth, manifest?)`
Push an image to the registry. Returns `PushResponse`.

#### `pullImageManifest(image, auth)`
Pull an image manifest. Returns `{ manifest, digest }`. If a multi-platform Image Index is encountered, automatically selects the platform-specific manifest.

#### `pullManifest(image, auth)`
Pull a manifest (either image or image index) from the registry. Returns `{ manifest, digest }`.

#### `pullManifestRaw(image, auth, acceptedMediaTypes)`
Pull a manifest as raw bytes. Returns a `Buffer`.

#### `pushManifest(image, manifest)`
Push a manifest (image or image index) to the registry. Returns the manifest URL.

#### `pushManifestList(reference, auth, manifest)`
Push a manifest list (image index). Returns manifest URL.

#### `pullReferrers(image, artifactType?)`
Pull referrers for an artifact (OCI 1.1 Referrers API). Returns `ImageIndex`.

#### `pullBlob(image, digest)`
Pull a blob from the registry. Returns a `Buffer`.

#### `pushBlob(image, data, digest)`
Push a blob to the registry. Returns the blob digest.

#### `blobExists(image, digest)`
Check if a blob exists in the registry. Returns `boolean`.

#### `mountBlob(target, source, digest)`
Mount a blob from one repository to another (cross-repository blob mounting).

#### `listTags(image, auth, n?, last?)`
List tags for a repository. Supports pagination via `n` (page size) and `last` (last tag from previous page). Returns `string[]`.

#### `fetchManifestDigest(image, auth)`
Fetch a manifest's digest without downloading the full manifest content. Returns the digest string.

#### `storeAuth(registry, auth)`
Pre-authenticate with a registry. Useful for storing credentials before performing multiple operations.

### Types

See the TypeScript definitions for complete type information.

## Building from Source

```bash
# Install dependencies
yarn install

# Build native module (release)
yarn build

# Build debug version
yarn build:debug

# Run tests
yarn test

# Lint
yarn lint
```

## Supported Platforms

- Windows x64 (MSVC)
- macOS x64 (Intel)
- macOS ARM64 (Apple Silicon)
- Linux x64 (glibc)
- Linux ARM64 (glibc)
- Linux x64 (musl/Alpine)
- Linux ARM64 (musl/Alpine)

## Contributing

See the [CONTRIBUTING.md](../../CONTRIBUTING.md) file in the repository root for contribution guidelines.

## License

Apache-2.0
