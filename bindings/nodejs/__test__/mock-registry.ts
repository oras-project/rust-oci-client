/**
 * Mock OCI Registry Server
 *
 * Simple HTTP server using the same fixtures as the native Rust tests.
 * Modeled after BadServer from tests/digest_validation.rs
 *
 * Also serves a multi-arch Image Index on /v2/test-multiarch/... for
 * testing platform resolution.
 */

import * as http from 'http'
import * as fs from 'fs'
import * as path from 'path'
import * as crypto from 'crypto'
import { fileURLToPath } from 'url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))

function sha256digest(buf: Buffer): string {
  return `sha256:${crypto.createHash('sha256').update(buf).digest('hex')}`
}

// ---------------------------------------------------------------------------
// Single-platform fixtures (from native Rust tests)
// ---------------------------------------------------------------------------

const FIXTURES_DIR = path.join(__dirname, '..', '..', '..', 'tests', 'fixtures')
const MANIFEST = fs.readFileSync(path.join(FIXTURES_DIR, 'manifest.json'))
const CONFIG = fs.readFileSync(path.join(FIXTURES_DIR, 'config.json'))
const BLOB = fs.readFileSync(path.join(FIXTURES_DIR, 'blob.tar.gz'))

export const MANIFEST_DIGEST = sha256digest(MANIFEST)
export const CONFIG_DIGEST = sha256digest(CONFIG)
export const BLOB_DIGEST = sha256digest(BLOB)

// ---------------------------------------------------------------------------
// Multi-arch fixtures: two platform-specific images (linux/amd64, linux/arm64)
// ---------------------------------------------------------------------------

const AMD64_CONFIG = Buffer.from(JSON.stringify({
  architecture: 'amd64',
  os: 'linux',
  config: {},
  rootfs: { type: 'layers', diff_ids: [] },
}))
const AMD64_LAYER = Buffer.from('amd64-layer-content')
const AMD64_CONFIG_DIGEST = sha256digest(AMD64_CONFIG)
const AMD64_LAYER_DIGEST = sha256digest(AMD64_LAYER)

const AMD64_MANIFEST_BUF = Buffer.from(JSON.stringify({
  schemaVersion: 2,
  mediaType: 'application/vnd.oci.image.manifest.v1+json',
  config: {
    mediaType: 'application/vnd.oci.image.config.v1+json',
    digest: AMD64_CONFIG_DIGEST,
    size: AMD64_CONFIG.length,
  },
  layers: [{
    mediaType: 'application/vnd.oci.image.layer.v1.tar',
    digest: AMD64_LAYER_DIGEST,
    size: AMD64_LAYER.length,
  }],
}))

const ARM64_CONFIG = Buffer.from(JSON.stringify({
  architecture: 'arm64',
  os: 'linux',
  config: {},
  rootfs: { type: 'layers', diff_ids: [] },
}))
const ARM64_LAYER = Buffer.from('arm64-layer-content')
const ARM64_CONFIG_DIGEST = sha256digest(ARM64_CONFIG)
const ARM64_LAYER_DIGEST = sha256digest(ARM64_LAYER)

const ARM64_MANIFEST_BUF = Buffer.from(JSON.stringify({
  schemaVersion: 2,
  mediaType: 'application/vnd.oci.image.manifest.v1+json',
  config: {
    mediaType: 'application/vnd.oci.image.config.v1+json',
    digest: ARM64_CONFIG_DIGEST,
    size: ARM64_CONFIG.length,
  },
  layers: [{
    mediaType: 'application/vnd.oci.image.layer.v1.tar',
    digest: ARM64_LAYER_DIGEST,
    size: ARM64_LAYER.length,
  }],
}))

export const AMD64_MANIFEST_DIGEST = sha256digest(AMD64_MANIFEST_BUF)
export const ARM64_MANIFEST_DIGEST = sha256digest(ARM64_MANIFEST_BUF)

const IMAGE_INDEX_BUF = Buffer.from(JSON.stringify({
  schemaVersion: 2,
  mediaType: 'application/vnd.oci.image.index.v1+json',
  manifests: [
    {
      mediaType: 'application/vnd.oci.image.manifest.v1+json',
      digest: AMD64_MANIFEST_DIGEST,
      size: AMD64_MANIFEST_BUF.length,
      platform: { architecture: 'amd64', os: 'linux' },
    },
    {
      mediaType: 'application/vnd.oci.image.manifest.v1+json',
      digest: ARM64_MANIFEST_DIGEST,
      size: ARM64_MANIFEST_BUF.length,
      platform: { architecture: 'arm64', os: 'linux' },
    },
  ],
}))
export const IMAGE_INDEX_DIGEST = sha256digest(IMAGE_INDEX_BUF)

const MULTIARCH_BLOBS = new Map<string, Buffer>([
  [AMD64_CONFIG_DIGEST, AMD64_CONFIG],
  [AMD64_LAYER_DIGEST, AMD64_LAYER],
  [ARM64_CONFIG_DIGEST, ARM64_CONFIG],
  [ARM64_LAYER_DIGEST, ARM64_LAYER],
])

const MULTIARCH_MANIFESTS = new Map<string, Buffer>([
  [AMD64_MANIFEST_DIGEST, AMD64_MANIFEST_BUF],
  [ARM64_MANIFEST_DIGEST, ARM64_MANIFEST_BUF],
])

// ---------------------------------------------------------------------------

const DIGEST_HEADER = 'Docker-Content-Digest'

export interface MockConfig {
  badManifest?: boolean
  badConfig?: boolean
  badBlob?: boolean
}

export class MockRegistry {
  private server: http.Server | null = null
  private _port = 0

  constructor(private config: MockConfig = {}) {}

  get port() {
    return this._port
  }
  get address() {
    return `127.0.0.1:${this._port}`
  }

  async start(): Promise<void> {
    this.server = http.createServer((req, res) => {
      const url = req.url || ''

      // /v2/ - API version check
      if (url === '/v2/' || url === '/v2') {
        res.writeHead(200)
        res.end('{}')
        return
      }

      // Route multi-arch repo separately
      if (url.startsWith('/v2/test-multiarch/')) {
        this.handleMultiarch(req, res, url)
        return
      }

      // /v2/{name}/manifests/{ref}
      if (url.includes('/manifests/')) {
        this.serveManifest(req, res)
        return
      }

      // /v2/{name}/blobs/{digest}
      if (url.includes('/blobs/')) {
        this.serveBlob(req, res, url)
        return
      }

      // /v2/{name}/tags/list
      if (url.includes('/tags/list')) {
        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ name: 'test', tags: ['latest', 'v1', 'v2'] }))
        return
      }

      res.writeHead(404)
      res.end()
    })

    return new Promise((resolve) => {
      this.server!.listen(0, '127.0.0.1', () => {
        const addr = this.server!.address() as { port: number }
        this._port = addr.port
        resolve()
      })
    })
  }

  // --- Single-platform routes (original /v2/test/...) ---

  private serveManifest(req: http.IncomingMessage, res: http.ServerResponse) {
    const digest = this.config.badManifest ? 'sha256:bad' : MANIFEST_DIGEST

    if (req.method === 'HEAD') {
      res.writeHead(200, {
        'Content-Type': 'application/vnd.docker.distribution.manifest.v2+json',
        [DIGEST_HEADER]: digest,
        'Content-Length': MANIFEST.length.toString(),
      })
      res.end()
    } else {
      res.writeHead(200, {
        'Content-Type': 'application/vnd.docker.distribution.manifest.v2+json',
        [DIGEST_HEADER]: digest,
      })
      res.end(MANIFEST)
    }
  }

  private serveBlob(req: http.IncomingMessage, res: http.ServerResponse, url: string) {
    const requestedDigest = decodeURIComponent(url.split('/blobs/')[1])

    let content: Buffer
    let digest: string

    if (requestedDigest === CONFIG_DIGEST) {
      content = CONFIG
      digest = this.config.badConfig ? 'sha256:bad' : CONFIG_DIGEST
    } else if (requestedDigest === BLOB_DIGEST) {
      content = BLOB
      digest = this.config.badBlob ? 'sha256:bad' : BLOB_DIGEST
    } else {
      res.writeHead(404)
      res.end()
      return
    }

    if (req.method === 'HEAD') {
      res.writeHead(200, {
        [DIGEST_HEADER]: digest,
        'Content-Length': content.length.toString(),
      })
      res.end()
    } else {
      res.writeHead(200, { [DIGEST_HEADER]: digest })
      res.end(content)
    }
  }

  // --- Multi-arch routes (/v2/test-multiarch/...) ---

  private handleMultiarch(req: http.IncomingMessage, res: http.ServerResponse, url: string) {
    if (url.includes('/manifests/')) {
      this.serveMultiarchManifest(req, res, url)
    } else if (url.includes('/blobs/')) {
      this.serveMultiarchBlob(req, res, url)
    } else if (url.includes('/tags/list')) {
      res.writeHead(200, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ name: 'test-multiarch', tags: ['latest'] }))
    } else {
      res.writeHead(404)
      res.end()
    }
  }

  private serveMultiarchManifest(req: http.IncomingMessage, res: http.ServerResponse, url: string) {
    const ref = decodeURIComponent(url.split('/manifests/')[1])

    if (ref === 'latest' || ref === IMAGE_INDEX_DIGEST) {
      const contentType = 'application/vnd.oci.image.index.v1+json'
      if (req.method === 'HEAD') {
        res.writeHead(200, {
          'Content-Type': contentType,
          [DIGEST_HEADER]: IMAGE_INDEX_DIGEST,
          'Content-Length': IMAGE_INDEX_BUF.length.toString(),
        })
        res.end()
      } else {
        res.writeHead(200, {
          'Content-Type': contentType,
          [DIGEST_HEADER]: IMAGE_INDEX_DIGEST,
        })
        res.end(IMAGE_INDEX_BUF)
      }
      return
    }

    const manifest = MULTIARCH_MANIFESTS.get(ref)
    if (manifest) {
      const contentType = 'application/vnd.oci.image.manifest.v1+json'
      if (req.method === 'HEAD') {
        res.writeHead(200, {
          'Content-Type': contentType,
          [DIGEST_HEADER]: ref,
          'Content-Length': manifest.length.toString(),
        })
        res.end()
      } else {
        res.writeHead(200, {
          'Content-Type': contentType,
          [DIGEST_HEADER]: ref,
        })
        res.end(manifest)
      }
      return
    }

    res.writeHead(404)
    res.end()
  }

  private serveMultiarchBlob(req: http.IncomingMessage, res: http.ServerResponse, url: string) {
    const requestedDigest = decodeURIComponent(url.split('/blobs/')[1])
    const content = MULTIARCH_BLOBS.get(requestedDigest)

    if (!content) {
      res.writeHead(404)
      res.end()
      return
    }

    if (req.method === 'HEAD') {
      res.writeHead(200, {
        [DIGEST_HEADER]: requestedDigest,
        'Content-Length': content.length.toString(),
      })
      res.end()
    } else {
      res.writeHead(200, { [DIGEST_HEADER]: requestedDigest })
      res.end(content)
    }
  }

  async stop(): Promise<void> {
    if (this.server) {
      return new Promise((resolve) => this.server!.close(() => resolve()))
    }
  }
}

