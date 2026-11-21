import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { DeviceRegistry } from './device-registry'
import { DEVICE_REGISTRY_FILENAME } from './mobile-pairing-files'

let dir: string

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'orca-device-registry-paired-change-'))
})

afterEach(() => {
  vi.useRealTimers()
  rmSync(dir, { recursive: true, force: true })
})

describe('paired device change notifications', () => {
  it('fires on pairing and revocation but not on offer mints or reconnect bookkeeping', () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] })
    const registry = new DeviceRegistry(dir)
    const onChanged = vi.fn()
    registry.setOnPairedDevicesChanged(onChanged)

    const offer = registry.getOrCreatePendingDevice('phone', 'mobile')
    expect(onChanged).not.toHaveBeenCalled()

    registry.updateLastSeenDeferred(offer.deviceId, undefined, 'v2')
    expect(onChanged).toHaveBeenCalledTimes(1)

    for (let i = 0; i < 3; i += 1) {
      registry.updateLastSeenDeferred(offer.deviceId, undefined, 'v2')
      vi.advanceTimersByTime(1000)
      registry.updateLastSeenDeferred(offer.deviceId)
      vi.advanceTimersByTime(1000)
    }
    expect(onChanged).toHaveBeenCalledTimes(1)

    registry.removeDevice(offer.deviceId)
    expect(onChanged).toHaveBeenCalledTimes(2)
  })
  it('fires when it adopts a revoke another process wrote to the file', () => {
    const registry = new DeviceRegistry(dir)
    const phone = registry.getOrCreatePendingDevice('phone', 'mobile')
    registry.updateLastSeenDeferred(phone.deviceId, undefined, 'v2')
    const onChanged = vi.fn()
    registry.setOnPairedDevicesChanged(onChanged)

    // An admin's script removes the row without going through this process.
    const registryPath = join(dir, DEVICE_REGISTRY_FILENAME)
    const rows: { deviceId: string }[] = JSON.parse(readFileSync(registryPath, 'utf8'))
    writeFileSync(
      registryPath,
      JSON.stringify(rows.filter((row) => row.deviceId !== phone.deviceId))
    )
    registry.getPendingDevice()

    expect(onChanged).toHaveBeenCalledTimes(1)
  })
})
