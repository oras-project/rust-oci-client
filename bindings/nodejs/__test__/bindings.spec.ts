/**
 * Tests for the Node.js bindings of rust-oci-client
 *
 * These tests validate that the NAPI bindings work correctly and produce
 * the same results as the native Rust implementation.
 *
 * Pull tests use a mock OCI registry server (no Docker Hub, no rate limits).
 * Push tests use a Zot registry container (requires Docker or Podman).
 */

import test from 'ava'
import * as crypto from 'crypto'
import {
  OciClient,
  anonymousAuth,
  basicAuth,
  bearerAuth,
  RegistryAuthType,
  ClientProtocol,
  CertificateEncoding,
  ManifestType,
  // Media type constants
  IMAGE_LAYER_MEDIA_TYPE,
  IMAGE_LAYER_GZIP_MEDIA_TYPE,
  IMAGE_CONFIG_MEDIA_TYPE,
  IMAGE_DOCKER_LAYER_GZIP_MEDIA_TYPE,
  OCI_IMAGE_MEDIA_TYPE,
  OCI_IMAGE_INDEX_MEDIA_TYPE,
  // Annotation constants
  ORG_OPENCONTAINERS_IMAGE_TITLE,
  ORG_OPENCONTAINERS_IMAGE_CREATED,
  ORG_OPENCONTAINERS_IMAGE_REF_NAME,
  // Types
  type RegistryAuth,
  type ClientConfig,
  type ImageLayer,
  type Config,
  type ImageData,
  type ImageManifest,
  type ImageIndex,
  type Descriptor,
  type PlatformSpec,
  type Manifest,
} from '../index.js'
import { MockRegistry, MANIFEST_DIGEST, CONFIG_DIGEST, BLOB_DIGEST } from './mock-registry.js'
import { ZotRegistry, shouldSkipZotTests } from './zot-registry.js'

// =============================================================================
// Authentication Tests
// =============================================================================

test('anonymousAuth - should create anonymous auth object', (t) => {
  const auth: RegistryAuth = anonymousAuth()
  t.truthy(auth)
  t.is(auth.authType, RegistryAuthType.Anonymous)
  t.is(auth.username, undefined)
  t.is(auth.password, undefined)
  t.is(auth.token, undefined)
})

test('basicAuth - should create basic auth object with credentials', (t) => {
  const auth: RegistryAuth = basicAuth('testuser', 'testpass')
  t.truthy(auth)
  t.is(auth.authType, RegistryAuthType.Basic)
  t.is(auth.username, 'testuser')
  t.is(auth.password, 'testpass')
  t.is(auth.token, undefined)
})

test('basicAuth - should handle empty credentials', (t) => {
  const auth: RegistryAuth = basicAuth('', '')
  t.is(auth.authType, RegistryAuthType.Basic)
  t.is(auth.username, '')
  t.is(auth.password, '')
})

test('bearerAuth - should create bearer auth object with token', (t) => {
  const auth: RegistryAuth = bearerAuth('my-secret-token')
  t.truthy(auth)
  t.is(auth.authType, RegistryAuthType.Bearer)
  t.is(auth.token, 'my-secret-token')
  t.is(auth.username, undefined)
  t.is(auth.password, undefined)
})

// =============================================================================
// OciClient Tests
// =============================================================================

test('OciClient - should create client with default configuration', (t) => {
  const client = new OciClient()
  t.truthy(client)
  t.true(client instanceof OciClient)
})

test('OciClient.withConfig - should create client with custom protocol (Http)', (t) => {
  const client = OciClient.withConfig({
    protocol: ClientProtocol.Http,
  })
  t.truthy(client)
  t.true(client instanceof OciClient)
})

test('OciClient.withConfig - should create client with custom protocol (Https)', (t) => {
  const client = OciClient.withConfig({
    protocol: ClientProtocol.Https,
  })
  t.truthy(client)
})

test('OciClient.withConfig - should create client with HttpsExcept protocol', (t) => {
  const client = OciClient.withConfig({
    protocol: ClientProtocol.HttpsExcept,
    httpsExceptRegistries: ['localhost:5000', '127.0.0.1:5000'],
  })
  t.truthy(client)
})

test('OciClient.withConfig - should create client with accept invalid certificates', (t) => {
  const client = OciClient.withConfig({
    acceptInvalidCertificates: true,
  })
  t.truthy(client)
})

test('OciClient.withConfig - should create client with concurrency settings', (t) => {
  const client = OciClient.withConfig({
    maxConcurrentUpload: 4,
    maxConcurrentDownload: 8,
  })
  t.truthy(client)
})

test('OciClient.withConfig - should create client with timeout settings', (t) => {
  const client = OciClient.withConfig({
    readTimeoutMs: 30000,
    connectTimeoutMs: 10000,
  })
  t.truthy(client)
})

test('OciClient.withConfig - should create client with proxy settings', (t) => {
  const client = OciClient.withConfig({
    httpsProxy: 'http://proxy.example.com:8080',
    httpProxy: 'http://proxy.example.com:8080',
    noProxy: 'localhost,127.0.0.1',
  })
  t.truthy(client)
})

test('OciClient.withConfig - should create client with all settings combined', (t) => {
  const config: ClientConfig = {
    protocol: ClientProtocol.Https,
    acceptInvalidCertificates: false,
    useMonolithicPush: false,
    maxConcurrentUpload: 8,
    maxConcurrentDownload: 16,
    defaultTokenExpirationSecs: 300,
    readTimeoutMs: 60000,
    connectTimeoutMs: 15000,
  }
  const client = OciClient.withConfig(config)
  t.truthy(client)
})

test('OciClient.withConfig - should create client with custom certificates', (t) => {
  const dummyCertPem = Buffer.from(`-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHBfpB+dEzxMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnVu
dXNlZDAeFw0yNDAxMDEwMDAwMDBaFw0yNTAxMDEwMDAwMDBaMBExDzANBgNVBAMM
BnVudXNlZDBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQC5mG0lCDMvz/n9WQH7dlfN
zQkFqW9sMSqvX9qPxN1LmQE7fv/9k1p7q8VDqy6RhDz1f9nNqvHXX1XqHqXJKJBp
AgMBAAGjUzBRMB0GA1UdDgQWBBQJ7W7lXPqXtdJ9gJ8cKo9E7VtZyjAfBgNVHSME
GDAWgBQJ7W7lXPqXtdJ9gJ8cKo9E7VtZyjAPBgNVHRMBAf8EBTADAQH/MA0GCSqG
SIb3DQEBCwUAA0EAG9NxyMEKYE8fzhzLgDz7MQMP3XL7kDqPqRnvJQGLNJQrvSj5
5M/hDp3eXrWzLgJPqPcC1H3B9cCNqLz8NB/32g==
-----END CERTIFICATE-----`)

  const config: ClientConfig = {
    protocol: ClientProtocol.Https,
    extraRootCertificates: [
      {
        encoding: CertificateEncoding.Pem,
        data: dummyCertPem,
      },
    ],
  }
  const client = OciClient.withConfig(config)
  t.truthy(client)
})

// =============================================================================
// Type Structure Tests
// =============================================================================

test('ImageLayer - should accept valid ImageLayer structure', (t) => {
  const layer: ImageLayer = {
    data: Buffer.from('test data'),
    mediaType: IMAGE_LAYER_GZIP_MEDIA_TYPE,
    annotations: { [ORG_OPENCONTAINERS_IMAGE_TITLE]: 'layer.tar.gz' },
  }
  t.true(layer.data instanceof Buffer)
  t.is(layer.mediaType, IMAGE_LAYER_GZIP_MEDIA_TYPE)
  t.truthy(layer.annotations)
})

test('ImageLayer - should accept ImageLayer without annotations', (t) => {
  const layer: ImageLayer = {
    data: Buffer.from('test'),
    mediaType: IMAGE_LAYER_MEDIA_TYPE,
  }
  t.is(layer.annotations, undefined)
})

test('Config - should accept valid Config structure', (t) => {
  const config: Config = {
    data: Buffer.from('{}'),
    mediaType: IMAGE_CONFIG_MEDIA_TYPE,
    annotations: { 'custom.annotation': 'value' },
  }
  t.true(config.data instanceof Buffer)
  t.is(config.mediaType, IMAGE_CONFIG_MEDIA_TYPE)
})

test('Descriptor - should accept valid Descriptor structure', (t) => {
  const descriptor: Descriptor = {
    mediaType: IMAGE_LAYER_GZIP_MEDIA_TYPE,
    digest: 'sha256:abc123def456',
    size: 1024,
    urls: ['https://example.com/blob'],
    annotations: { [ORG_OPENCONTAINERS_IMAGE_TITLE]: 'test' },
  }
  t.truthy(descriptor.mediaType)
  t.truthy(descriptor.digest)
  t.is(descriptor.size, 1024)
})

test('Descriptor - should accept minimal Descriptor', (t) => {
  const descriptor: Descriptor = {
    mediaType: IMAGE_LAYER_MEDIA_TYPE,
    digest: 'sha256:abc',
    size: 0,
  }
  t.is(descriptor.urls, undefined)
  t.is(descriptor.annotations, undefined)
})

test('PlatformSpec - should accept full PlatformSpec', (t) => {
  const platform: PlatformSpec = {
    architecture: 'amd64',
    os: 'linux',
    osVersion: '5.4.0',
    osFeatures: ['sse4'],
    variant: 'v8',
    features: ['avx'],
  }
  t.is(platform.architecture, 'amd64')
  t.is(platform.os, 'linux')
})

test('PlatformSpec - should accept minimal PlatformSpec', (t) => {
  const platform: PlatformSpec = {
    architecture: 'arm64',
    os: 'darwin',
  }
  t.is(platform.osVersion, undefined)
})

test('ImageManifest - should accept valid ImageManifest structure', (t) => {
  const manifest: ImageManifest = {
    schemaVersion: 2,
    mediaType: OCI_IMAGE_MEDIA_TYPE,
    config: {
      mediaType: IMAGE_CONFIG_MEDIA_TYPE,
      digest: 'sha256:config123',
      size: 512,
    },
    layers: [
      {
        mediaType: IMAGE_LAYER_GZIP_MEDIA_TYPE,
        digest: 'sha256:layer123',
        size: 2048,
      },
    ],
    artifactType: 'application/vnd.example.artifact',
    annotations: { [ORG_OPENCONTAINERS_IMAGE_CREATED]: '2024-01-01T00:00:00Z' },
  }
  t.is(manifest.schemaVersion, 2)
  t.is(manifest.config.digest, 'sha256:config123')
  t.is(manifest.layers.length, 1)
})

test('ImageIndex - should accept valid ImageIndex structure', (t) => {
  const index: ImageIndex = {
    schemaVersion: 2,
    mediaType: OCI_IMAGE_INDEX_MEDIA_TYPE,
    manifests: [
      {
        mediaType: OCI_IMAGE_MEDIA_TYPE,
        digest: 'sha256:manifest123',
        size: 1024,
        platform: {
          architecture: 'amd64',
          os: 'linux',
        },
      },
      {
        mediaType: OCI_IMAGE_MEDIA_TYPE,
        digest: 'sha256:manifest456',
        size: 1024,
        platform: {
          architecture: 'arm64',
          os: 'linux',
        },
      },
    ],
    annotations: { [ORG_OPENCONTAINERS_IMAGE_REF_NAME]: 'latest' },
  }
  t.is(index.schemaVersion, 2)
  t.is(index.manifests.length, 2)
})

// =============================================================================
// Registry Operations using Mock Server
// =============================================================================

let mockRegistry: MockRegistry
let mockClient: OciClient
let MOCK_REGISTRY: string

test.before(async () => {
  mockRegistry = new MockRegistry()
  await mockRegistry.start()
  MOCK_REGISTRY = mockRegistry.address
  mockClient = OciClient.withConfig({ protocol: ClientProtocol.Http })
  console.log(`🧪 Mock registry started on ${MOCK_REGISTRY}`)
})

test.after(async () => {
  await mockRegistry.stop()
})

test.serial('pullManifest - should pull manifest from mock registry', async (t) => {
  const result = await mockClient.pullManifest(
    `${MOCK_REGISTRY}/test:latest`,
    anonymousAuth()
  )

  t.truthy(result)
  t.truthy(result.manifest)
  t.is(result.digest, MANIFEST_DIGEST)
  t.is(result.manifest.manifestType, ManifestType.Image)
  t.is(result.manifest.image!.schemaVersion, 2)
})

test.serial('pullManifest - should pull manifest by digest', async (t) => {
  const result = await mockClient.pullManifest(
    `${MOCK_REGISTRY}/test@${MANIFEST_DIGEST}`,
    anonymousAuth()
  )

  t.is(result.digest, MANIFEST_DIGEST)
})

test.serial('fetchManifestDigest - should fetch manifest digest without downloading full manifest', async (t) => {
  const digest = await mockClient.fetchManifestDigest(
    `${MOCK_REGISTRY}/test:latest`,
    anonymousAuth()
  )

  t.is(digest, MANIFEST_DIGEST)
})

test.serial('listTags - should list tags from mock registry', async (t) => {
  const tags = await mockClient.listTags(
    `${MOCK_REGISTRY}/test`,
    anonymousAuth(),
    10,
    undefined
  )

  t.true(tags.includes('latest'))
  t.true(tags.includes('v1'))
})

test.serial('pullBlob - should pull config blob by digest', async (t) => {
  const configData = await mockClient.pullBlob(
    `${MOCK_REGISTRY}/test:latest`,
    CONFIG_DIGEST
  )

  t.true(configData instanceof Buffer)
  t.true(configData.length > 0)

  const configJson = JSON.parse(configData.toString('utf-8'))
  t.is(configJson.architecture, 'amd64')
  t.is(configJson.os, 'linux')
})

test.serial('pullBlob - should pull layer blob by digest', async (t) => {
  const layerData = await mockClient.pullBlob(
    `${MOCK_REGISTRY}/test:latest`,
    BLOB_DIGEST
  )

  t.true(layerData instanceof Buffer)
  t.true(layerData.length > 0)
})

test.serial('blobExists - should return true for existing blob', async (t) => {
  const exists = await mockClient.blobExists(
    `${MOCK_REGISTRY}/test:latest`,
    CONFIG_DIGEST
  )
  t.true(exists)
})

test.serial('blobExists - should return false for non-existing blob', async (t) => {
  const fakeDigest = 'sha256:0000000000000000000000000000000000000000000000000000000000000000'
  const exists = await mockClient.blobExists(
    `${MOCK_REGISTRY}/test:latest`,
    fakeDigest
  )
  t.false(exists)
})

test.serial('pull - should pull full image with layers', async (t) => {
  const imageData: ImageData = await mockClient.pull(
    `${MOCK_REGISTRY}/test@${MANIFEST_DIGEST}`,
    anonymousAuth(),
    [IMAGE_DOCKER_LAYER_GZIP_MEDIA_TYPE]
  )

  t.truthy(imageData)
  t.truthy(imageData.layers)
  t.is(imageData.layers.length, 1)
  t.truthy(imageData.config)
  t.true(imageData.config.data instanceof Buffer)
  t.truthy(imageData.digest)

  t.truthy(imageData.manifest)
  t.is(imageData.manifest!.schemaVersion, 2)
  t.is(imageData.manifest!.layers!.length, imageData.layers.length)

  t.true(imageData.layers[0].data.length > 0)
})

test.serial('Error Handling - should throw error for invalid image reference', async (t) => {
  await t.throwsAsync(
    mockClient.pullManifest('invalid:::reference', anonymousAuth())
  )
})

test.serial('Error Handling - should throw error for non-existent blob', async (t) => {
  await t.throwsAsync(
    mockClient.pullBlob(
      `${MOCK_REGISTRY}/test:latest`,
      'sha256:nonexistent0000000000000000000000000000000000000000000000000000'
    )
  )
})

test.serial('storeAuth - should store auth for later use', async (t) => {
  const client = new OciClient()

  await t.notThrowsAsync(client.storeAuth('docker.io', anonymousAuth()))
  await t.notThrowsAsync(client.storeAuth('ghcr.io', basicAuth('user', 'token')))
})

// =============================================================================
// Push Tests with Zot Registry
// =============================================================================

const skipZot = shouldSkipZotTests()

const zot = new ZotRegistry()
let ZOT_REGISTRY: string
let ZOT_REPO: string
let zotClient: OciClient

if (!skipZot) {
  test.before(async () => {
    await zot.start()
    ZOT_REGISTRY = zot.address
    ZOT_REPO = zot.repo('test-oci-client')
    zotClient = zot.createClient()
  })

  test.after(async () => {
    await zot.stop()
  })
}

const zotTest = skipZot ? test.skip : test.serial

zotTest('pushBlob - should push a blob to the registry', async (t) => {
  const testData = Buffer.from('Hello, OCI World!')
  const hash = crypto.createHash('sha256').update(testData).digest('hex')
  const digest = `sha256:${hash}`

  const result = await zotClient.pushBlob(`${ZOT_REPO}:test`, testData, digest)

  t.truthy(result)
  t.true(result.includes(digest))
})

zotTest('pushBlob - should verify pushed blob exists', async (t) => {
  const testData = Buffer.from('Test blob data for existence check')
  const hash = crypto.createHash('sha256').update(testData).digest('hex')
  const digest = `sha256:${hash}`

  await zotClient.pushBlob(`${ZOT_REPO}:test`, testData, digest)

  const exists = await zotClient.blobExists(`${ZOT_REPO}:test`, digest)
  t.true(exists)
})

zotTest('pushBlob - should pull back the pushed blob with same content', async (t) => {
  const originalData = Buffer.from('Roundtrip test data: ' + Date.now())
  const hash = crypto.createHash('sha256').update(originalData).digest('hex')
  const digest = `sha256:${hash}`

  await zotClient.pushBlob(`${ZOT_REPO}:test`, originalData, digest)

  const pulledData = await zotClient.pullBlob(`${ZOT_REPO}:test`, digest)

  t.true(pulledData instanceof Buffer)
  t.is(pulledData.toString(), originalData.toString())
  t.is(pulledData.length, originalData.length)
})

zotTest('pushManifest - should push a simple OCI image manifest', async (t) => {
  const configData = Buffer.from(JSON.stringify({
    architecture: 'amd64',
    os: 'linux',
    config: {},
    rootfs: { type: 'layers', diff_ids: [] },
  }))
  const configHash = crypto.createHash('sha256').update(configData).digest('hex')
  const configDigest = `sha256:${configHash}`

  const layerData = Buffer.from('test layer content')
  const layerHash = crypto.createHash('sha256').update(layerData).digest('hex')
  const layerDigest = `sha256:${layerHash}`

  await zotClient.pushBlob(`${ZOT_REPO}:v1`, configData, configDigest)
  await zotClient.pushBlob(`${ZOT_REPO}:v1`, layerData, layerDigest)

  const imageManifest: ImageManifest = {
    schemaVersion: 2,
    mediaType: OCI_IMAGE_MEDIA_TYPE,
    config: {
      mediaType: IMAGE_CONFIG_MEDIA_TYPE,
      digest: configDigest,
      size: configData.length,
    },
    layers: [
      {
        mediaType: IMAGE_LAYER_MEDIA_TYPE,
        digest: layerDigest,
        size: layerData.length,
      },
    ],
  }

  const manifest: Manifest = {
    manifestType: ManifestType.Image,
    image: imageManifest,
  }

  const manifestUrl = await zotClient.pushManifest(`${ZOT_REPO}:v1`, manifest)

  t.truthy(manifestUrl)
  t.true(manifestUrl.includes(ZOT_REGISTRY))
})

zotTest('push - should push a complete image using the push() method', async (t) => {
  const tag = `full-${Date.now()}`

  const layer1Data = Buffer.from('Layer 1 content: ' + Date.now())
  const layer2Data = Buffer.from('Layer 2 content: ' + Date.now())

  const layers: ImageLayer[] = [
    {
      data: layer1Data,
      mediaType: IMAGE_LAYER_MEDIA_TYPE,
      annotations: { [ORG_OPENCONTAINERS_IMAGE_TITLE]: 'layer1.tar' },
    },
    {
      data: layer2Data,
      mediaType: IMAGE_LAYER_MEDIA_TYPE,
      annotations: { [ORG_OPENCONTAINERS_IMAGE_TITLE]: 'layer2.tar' },
    },
  ]

  const configJson = JSON.stringify({
    architecture: 'amd64',
    os: 'linux',
    config: {
      Env: ['PATH=/usr/local/bin:/usr/bin:/bin'],
      Cmd: ['/bin/sh'],
    },
    rootfs: {
      type: 'layers',
      diff_ids: [],
    },
    history: [
      { created: new Date().toISOString(), created_by: 'test' },
    ],
  })

  const config: Config = {
    data: Buffer.from(configJson),
    mediaType: IMAGE_CONFIG_MEDIA_TYPE,
  }

  const response = await zotClient.push(
    `${ZOT_REPO}:${tag}`,
    layers,
    config,
    anonymousAuth(),
    undefined
  )

  t.truthy(response)
  t.truthy(response.configUrl)
  t.truthy(response.manifestUrl)
  t.true(response.manifestUrl.includes(ZOT_REGISTRY))

  const pulledResult = await zotClient.pullManifest(
    `${ZOT_REPO}:${tag}`,
    anonymousAuth()
  )

  t.is(pulledResult.manifest.manifestType, ManifestType.Image)
  const pulledManifest = pulledResult.manifest.image!
  t.is(pulledManifest.layers!.length, 2)
})

