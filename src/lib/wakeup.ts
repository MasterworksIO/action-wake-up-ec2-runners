import AWS from 'aws-sdk'
import { Instance, InstanceStateChangeList, FilterList } from 'aws-sdk/clients/ec2'

import log, { objectDebug } from './log'

const cw = new AWS.CloudWatch({ apiVersion: '2010-08-01' })
const ec2 = new AWS.EC2({ apiVersion: '2016-11-15' })

function swap<T>(arr: T[], i: number, j: number): T[] {
  [arr[i], arr[j]] = [arr[j], arr[i]]
  return arr
}

function shuffle<T>(arr: T[]): T[] {
  const copy = arr.slice()

  for (let i = 0; i < copy.length; i++) {
    const j = Math.floor(Math.random() * (i + 1))
    swap(copy, i, j)
  }

  return copy
}

function wait<T>(ms: number, x?: T): Promise<T> {
  return new Promise((resolve) => setTimeout(() => resolve(x), ms))
}

async function getInstances(tags: Record<string, string>): Promise<Instance[]> {
  const Filters: FilterList = Object.entries(tags).map(([key, val]) => ({
    Name: `tag:${key}`,
    Values: val.split(','),
  }))

  objectDebug('filters', Filters)

  // AWS SDK throws if Filters is an empty array or empty object is set as options.
  const { Reservations } = Filters.length
    ? await ec2.describeInstances({ Filters }).promise()
    : await ec2.describeInstances().promise()

  if (Reservations === undefined) {
    return []
  }

  objectDebug('Reservations', Reservations)

  return Reservations.map(({ Instances }) => Instances ?? []).flat()
}

async function start(instances: Instance[], retries = 5): Promise<InstanceStateChangeList> {
  try {
    const InstanceIds = instances.map((instance) => instance.InstanceId as string)
    const { StartingInstances } = await ec2.startInstances({ InstanceIds }).promise()

    return StartingInstances ?? []
  } catch (err) {
    if (err.code === 'IncorrectSpotRequestState') {
      if (retries) {
        log.warn(`CI start: some spot instances are not ready, retrying in 3sec...`)
        await wait(3000)
        return start(instances, retries - 1)
      }

      log.error(`CI start: Couldn't get spot instance to start`)
      throw err
    }

    throw err
  }
}

type WakeupOptions = {
  tags: Record<string, string>
  concurrency: number
}

type GroupedInstances = Record<string, Instance[]>

type InstanceCPUUsageLimits = {
  max: number
  min: number
}

export default async function wakeup({
  tags,
  concurrency,
}: WakeupOptions): Promise<InstanceStateChangeList> {
  const instances = await getInstances(tags)

  objectDebug('instances', instances)

  const { running = [], stopped = [], pending = [] } = instances.reduce(
    (acc: GroupedInstances, instance: Instance): GroupedInstances => {
      const key = instance?.State?.Name ?? 'unknown'

      if (acc[key]) {
        acc[key].push(instance)
      } else {
        acc[key] = [instance]
      }

      return acc
    },
    {}
  )

  log.info(
    [
      'wakeup: instances found',
      `    running: ${running.length}`,
      `    stopped: ${stopped.length}`,
      `    pending: ${pending.length}`,
    ].join('\n')
  )

  const usage = await Promise.all(
    running.map((instance) =>
      cw
        .getMetricStatistics(
          {
            Namespace: 'AWS/EC2',
            MetricName: 'CPUUtilization',
            Dimensions: [
              {
                Name: 'InstanceId',
                Value: String(instance.InstanceId),
              },
            ],
            Period: 1,
            StartTime: new Date(Date.now() - 300e3),
            EndTime: new Date(Date.now()),
            Statistics: ['Maximum'],
          },
          undefined
        )
        .promise()
        .then(({ Datapoints = [] }) => {
          objectDebug('DataPoints', Datapoints)

          const instanceUsage: InstanceCPUUsageLimits = Datapoints.length
            ? Datapoints.reduce(
                (acc: InstanceCPUUsageLimits, point) => ({
                  max: Math.max(acc.max, point.Maximum ?? acc.max),
                  min: Math.min(acc.min, point.Maximum ?? acc.min),
                }),
                { min: Infinity, max: -Infinity }
              )
            : { min: 0, max: 100 }

          return {
            instance,
            ...instanceUsage,
          }
        })
    )
  )

  const { busy, idle }: GroupedInstances = usage.reduce(
    (acc: GroupedInstances, { instance, max }) => {
      if (max > 10) {
        acc.busy.push(instance)
      } else {
        acc.idle.push(instance)
      }

      return acc
    },
    { busy: [], idle: [] } as GroupedInstances
  )

  if (running.length) {
    log.info(
      `wakeup: out of the running instances, ${busy.length} are busy and ${idle.length} are idle`
    )
  }

  const availableCount = idle.length + pending.length
  const deficitCount = Math.max(0, concurrency - availableCount)

  if (!deficitCount) {
    log.info('wakeup: concurrency requirements met, nothing to do')
    return []
  }

  if (!stopped.length) {
    log.warn('wakeup: there are no more available runners, nothing to do')
    return []
  }

  const queueCount = Math.min(stopped.length, deficitCount)
  const toStartInstances = shuffle(stopped).slice(0, queueCount)

  log.info(
    [
      'wakeup: starting the following instances',
      ...toStartInstances.map(({ InstanceId }) => `    ${InstanceId}`),
    ].join('\n')
  )

  const startingInstances = (await start(toStartInstances)) ?? []

  log.info(
    [
      'wakeup: request sent',
      ...startingInstances.map(
        ({ CurrentState, InstanceId }) => `    ${InstanceId}: ${CurrentState?.Name ?? 'unknown'}`
      ),
    ].join('\n')
  )

  return startingInstances
}
