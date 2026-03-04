/**
 * Mock OCI Registry Server
 *
 * Simple HTTP server using the same fixtures as the native Rust tests.
 * Modeled after BadServer from tests/digest_validation.rs
 */

import * as http from 'http'
import * as fs from 'fs'
import * as path from 'path'
import * as crypto from 'crypto'
import { fileURLToPath } from 'url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))

// Load fixtures from the native project (reuse, don't copy)
const FIXTURES_DIR = path.join(__dirname, '..', '..', '..', 'tests', 'fixtures')
const MANIFEST = fs.readFileSync(path.join(FIXTURES_DIR, 'manifest.json'))
const CONFIG = fs.readFileSync(path.join(FIXTURES_DIR, 'config.json'))
const BLOB = fs.readFileSync(path.join(FIXTURES_DIR, 'blob.tar.gz'))

// Compute digests (same as Rust tests)
export const MANIFEST_DIGEST = `sha256:${crypto.createHash('sha256').update(MANIFEST).digest('hex')}`
export const CONFIG_DIGEST = `sha256:${crypto.createHash('sha256').update(CONFIG).digest('hex')}`
export const BLOB_DIGEST = `sha256:${crypto.createHash('sha256').update(BLOB).digest('hex')}`

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

  async stop(): Promise<void> {
    if (this.server) {
      return new Promise((resolve) => this.server!.close(() => resolve()))
    }
  }
}

