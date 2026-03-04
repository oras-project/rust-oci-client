/**
 * Zot Registry Utilities
 *
 * Shared utilities for managing a Zot registry container in tests.
 * The registry is persistent across test runs to avoid issues.
 */

import { execSync } from 'child_process'
import * as net from 'net'
import { OciClient, ClientProtocol } from '../index.js'

export const CONTAINER_NAME_PREFIX = 'oci-client-test-registry'
export const ZOT_IMAGE = 'ghcr.io/project-zot/zot-minimal:latest'

// Port range for registry instances (use high ports to avoid conflicts)
const PORT_RANGE_START = 15000
const PORT_RANGE_SIZE = 10000

// Counter to ensure unique container names within the same process
let instanceCounter = 0

/**
 * Get a random starting port to avoid race conditions when multiple test files start at once
 */
function getRandomStartPort(): number {
  return PORT_RANGE_START + Math.floor(Math.random() * PORT_RANGE_SIZE)
}

export type ContainerRuntime = 'podman' | 'docker'

/**
 * Check if a port is available
 */
export async function isPortAvailable(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const server = net.createServer()
    server.once('error', () => resolve(false))
    server.once('listening', () => {
      server.close()
      resolve(true)
    })
    server.listen(port)
  })
}

/**
 * Find an available port starting from a given port
 */
export async function findAvailablePort(startPort: number): Promise<number> {
  for (let port = startPort; port < startPort + 100; port++) {
    if (await isPortAvailable(port)) {
      return port
    }
  }
  throw new Error(`No available port found in range ${startPort}-${startPort + 100}`)
}

/**
 * Wait for the registry to be ready
 */
export async function waitForRegistry(port: number, maxAttempts = 30): Promise<void> {
  for (let i = 0; i < maxAttempts; i++) {
    try {
      const response = await fetch(`http://localhost:${port}/v2/`)
      if (response.ok) {
        console.log(`✅ Zot registry is ready on port ${port}`)
        return
      }
    } catch {
      // Registry not ready yet
    }
    await new Promise((resolve) => setTimeout(resolve, 1000))
  }
  throw new Error(`Registry failed to start on port ${port}`)
}

// Cache the runtime detection result
let cachedRuntime: ContainerRuntime | null | undefined = undefined

/**
 * Detect available container runtime (cached)
 */
export function detectContainerRuntime(): ContainerRuntime | null {
  if (cachedRuntime !== undefined) {
    return cachedRuntime
  }

  const envRuntime = process.env.CONTAINER_RUNTIME?.toLowerCase()
  if (envRuntime === 'podman' || envRuntime === 'docker') {
    try {
      execSync(`${envRuntime} --version`, { stdio: 'ignore' })
      console.log(`🐳 Using container runtime from CONTAINER_RUNTIME env: ${envRuntime}`)
      cachedRuntime = envRuntime
      return envRuntime
    } catch {
      console.warn(`⚠️  CONTAINER_RUNTIME=${envRuntime} specified but not available`)
    }
  }

  try {
    execSync('podman --version', { stdio: 'ignore' })
    console.log('🐳 Auto-detected container runtime: podman')
    cachedRuntime = 'podman'
    return 'podman'
  } catch {
    // podman not available
  }

  try {
    execSync('docker --version', { stdio: 'ignore' })
    console.log('🐳 Auto-detected container runtime: docker')
    cachedRuntime = 'docker'
    return 'docker'
  } catch {
    // docker not available
  }

  cachedRuntime = null
  return null
}

/**
 * Zot Registry Manager
 *
 * Manages the lifecycle of a Zot registry container for testing.
 * The registry persists between test runs - it's only started if not already running.
 *
 * To stop the registry manually, run:
 *   podman rm -f oci-client-test-registry
 * or
 *   docker rm -f oci-client-test-registry
 */
export class ZotRegistry {
  private _port: number = 0
  private _runtime: ContainerRuntime | null = null
  private _started: boolean = false
  private _containerName: string

  constructor() {
    // Generate unique container name to avoid conflicts when test files run in parallel
    this._containerName = `${CONTAINER_NAME_PREFIX}-${process.pid}-${++instanceCounter}`
  }

  get port(): number {
    return this._port
  }
  get address(): string {
    return `localhost:${this._port}`
  }
  get runtime(): ContainerRuntime | null {
    return this._runtime
  }
  get isStarted(): boolean {
    return this._started
  }
  get containerName(): string {
    return this._containerName
  }

  /**
   * Start the Zot registry container.
   * Each instance starts its own container with a unique name.
   */
  async start(): Promise<void> {
    this._runtime = detectContainerRuntime()

    if (!this._runtime) {
      throw new Error('No container runtime (podman/docker) available')
    }

    console.log(`🚀 Starting Zot registry using ${this._runtime}...`)

    // Use random starting port to avoid race conditions when parallel test files start
    const startPort = getRandomStartPort()
    this._port = await findAvailablePort(startPort)

    // Clean up any existing stopped container with same name
    try {
      execSync(`${this._runtime} rm -f ${this._containerName} 2>/dev/null`, { stdio: 'ignore' })
    } catch {
      // Ignore errors
    }

    // Start Zot registry
    execSync(`${this._runtime} run -d --name ${this._containerName} -p ${this._port}:5000 ${ZOT_IMAGE}`, {
      stdio: 'inherit',
    })

    await waitForRegistry(this._port)
    this._started = true
  }

  /**
   * Stop the Zot registry container.
   *
   * By default, the container is stopped after tests complete.
   * Set KEEP_ZOT_REGISTRY=1 to keep it running for faster subsequent test runs.
   */
  async stop(): Promise<void> {
    if (!this._started) return

    const shouldKeep = process.env.KEEP_ZOT_REGISTRY === '1' || process.env.KEEP_ZOT_REGISTRY === 'true'

    if (shouldKeep) {
      console.log('♻️  Keeping Zot registry running (KEEP_ZOT_REGISTRY=1)')
      return
    }

    if (this._runtime) {
      console.log('🧹 Stopping Zot registry container...')
      try {
        execSync(`${this._runtime} rm -f ${this._containerName}`, { stdio: 'ignore' })
      } catch {
        // Ignore errors
      }
    }

    this._started = false
  }

  /**
   * Create an OCI client configured for this registry
   */
  createClient(): OciClient {
    return OciClient.withConfig({
      protocol: ClientProtocol.Http,
    })
  }

  /**
   * Get a repository reference for this registry
   */
  repo(name: string): string {
    return `${this.address}/${name}`
  }
}

// Cache the skip check result
let cachedSkipResult: boolean | undefined = undefined

/**
 * Check if Zot tests should be skipped (cached)
 */
export function shouldSkipZotTests(): boolean {
  if (cachedSkipResult !== undefined) {
    return cachedSkipResult
  }

  // Check if tests are explicitly disabled (e.g., on Windows/macOS CI where Linux containers aren't available)
  if (process.env.REQUIRE_PUSH_TESTS === 'false') {
    console.log('⏭️  Skipping Zot tests: REQUIRE_PUSH_TESTS is false')
    cachedSkipResult = true
    return true
  }

  const runtime = detectContainerRuntime()
  if (!runtime) {
    const requireTests = process.env.REQUIRE_PUSH_TESTS === 'true'
    if (requireTests) {
      throw new Error('REQUIRE_PUSH_TESTS is set but no container runtime (podman/docker) is available')
    }
    console.log('⏭️  Skipping Zot tests: No container runtime available')
    cachedSkipResult = true
    return true
  }

  cachedSkipResult = false
  return false
}

