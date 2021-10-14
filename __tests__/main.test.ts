import * as process from 'process'
import * as cp from 'child_process'
import * as path from 'path'

test('test runs', () => {
  const ip = path.join(__dirname, '..', 'dist', 'index.js')
  const options: cp.ExecSyncOptions = {
    env: process.env,
  }

  console.log(cp.execSync(`node ${ip}`, options).toString())
})
