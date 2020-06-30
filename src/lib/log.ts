import log from 'loglevel'

if (process.env.LOG_LEVEL) {
  log.setLevel(process.env.LOG_LEVEL as log.LogLevelDesc)
}

export const objectDebug = (name: string, content: Record<string, any>): void => {
  const paddedContent = JSON.stringify(content, null, 2)
    .split('\n')
    .map((line) => `    ${line}`)
    .join('\n')

  log.debug([`wakeup: ${name} contents`, paddedContent].join('\n'))
}

export default log
