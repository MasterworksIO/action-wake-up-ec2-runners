import * as core from '@actions/core'
import AWS from 'aws-sdk'

import log, { objectDebug } from './lib/log'

async function run(): Promise<void> {
  try {
    const options = {
      concurrency: Number.parseInt(core.getInput('concurrency') || '1', 10),
      tags: JSON.parse(core.getInput('tags') || '{}'),
      awsRegion: core.getInput('aws-region'),
    }

    objectDebug('options', options)

    if (options.awsRegion) {
      log.info(`wakeup: overriding AWS Region to use ${options.awsRegion}`)
      AWS.config.update({ region: options.awsRegion })
    }

    const { default: wakeup } = await import('./lib/wakeup')

    await wakeup(options)
  } catch (error) {
    console.trace(error)
    core.setFailed(error.message)
  }
}

run()
