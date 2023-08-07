import * as process from 'process'
import * as cp from 'child_process'
import * as path from 'path'

test('it runs without failing', () => {
  const ip = path.join(__dirname, '..', 'dist', 'index.js')
  const options: cp.ExecSyncOptions = {
    env: process.env,
  }

  expect(() => {
    // eslint-disable-next-line no-sync
    console.log(cp.execSync(`node ${ip}`, options).toString())
  }).not.toThrow()
})
