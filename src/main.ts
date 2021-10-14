import * as core from '@actions/core'

import { objectDebug } from './lib/log'

type ActionOptions = {
  concurrency: number
  retries: number
  tags: Record<string, string>
}

async function run(): Promise<void> {
  try {
    let tags: unknown = JSON.parse(core.getInput('tags') || '{}')

    if (typeof tags !== 'object' || !tags) {
      tags = {}
    }

    const options = {
      concurrency: Number.parseInt(core.getInput('concurrency') || '1', 10),
      retries: Number.parseInt(core.getInput('retries') || '5', 10),
      tags,
    } as ActionOptions

    objectDebug('options', options)

    const { default: wakeup } = await import('./lib/wakeup')

    await wakeup(options)
  } catch (error: unknown) {
    console.trace(error)
    core.setFailed(String(error))
  }
}

void run()
