import { readFileSync } from 'node:fs'
const profile = JSON.parse(readFileSync(process.argv[2], 'utf8'))
const nodes = new Map(profile.nodes.map(node => [node.id, node]))
const counts = {}
for (const id of profile.samples) {
  const { functionName: name, url } = nodes.get(id).callFrame
  const text = `${url} ${name}`
  const group = name === '(idle)' ? 'idle' : name === '(garbage collector)' ? 'gc' : /unmask|websocket|sender|receiver|splice-forwarder|writev|stream_base_commons/.test(text) ? 'splice/socket/ws' : /json/i.test(name) ? 'json' : /crypto|nacl|jose/i.test(text) ? 'crypto' : /sqlite|database|postgres/i.test(text) ? 'db' : 'other'
  counts[group] = (counts[group] || 0) + 1
}
console.log(JSON.stringify({ samples: profile.samples.length, counts }, null, 2))
