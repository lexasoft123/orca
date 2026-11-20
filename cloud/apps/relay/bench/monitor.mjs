import { appendFileSync } from 'node:fs'
import { monitorEventLoopDelay } from 'node:perf_hooks'
const histogram = monitorEventLoopDelay({ resolution: 10 })
histogram.enable()
let last = process.cpuUsage()
let lastTime = process.hrtime.bigint()
process.on('SIGUSR2', () => {
  const cpu = process.cpuUsage(last)
  const now = process.hrtime.bigint()
  const elapsedMs = Number(now - lastTime) / 1e6
  appendFileSync(process.env.BENCH_STATS, JSON.stringify({ elapsedMs, cpuMs: (cpu.user + cpu.system) / 1000, rss: process.memoryUsage.rss(), lagP99Ms: histogram.percentile(99) / 1e6, lagMaxMs: histogram.max / 1e6 }) + '\n')
  last = process.cpuUsage(); lastTime = now; histogram.reset()
})
