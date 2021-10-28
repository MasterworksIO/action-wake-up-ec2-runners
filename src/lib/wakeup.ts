import type { Instance, Filter, InstanceStateChange } from '@aws-sdk/client-ec2'
import {
  EC2Client,
  DescribeInstancesCommand,
  StartInstancesCommand,
  DescribeRegionsCommand,
} from '@aws-sdk/client-ec2'
import { CloudWatchClient, GetMetricStatisticsCommand } from '@aws-sdk/client-cloudwatch'

import log, { objectDebug } from './log'

function isObject(value: unknown): value is Record<PropertyKey, unknown> {
  return typeof value === 'object' && value !== null
}

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

async function wait<T>(ms: number, x?: T): Promise<T | undefined> {
  return new Promise((resolve) => setTimeout(() => resolve(x), ms))
}

async function getInstances(tags: Record<string, string>): Promise<Instance[]> {
  const instances: Instance[] = []

  const Filters: Filter[] = Object.entries(tags).map(([key, val]) => ({
    Name: `tag:${key}`,
    Values: val.split(','),
  }))

  objectDebug('filters', Filters)

  const { Regions } = await new EC2Client({}).send(new DescribeRegionsCommand({}))

  if (!Regions) {
    log.info(`No regions found for the configured account`)
    return instances
  }

  objectDebug('regions', Regions)

  const reservations = (
    await Promise.all(
      Regions.map(async ({ RegionName }) => {
        const { Reservations } = await new EC2Client({ region: RegionName }).send(
          new DescribeInstancesCommand({ Filters })
        )

        if (Reservations?.length) {
          objectDebug(`${RegionName} reservations`, Reservations)
          return Reservations
        }

        log.info(`No reservations found in ${RegionName}`)

        return []
      })
    )
  ).flat()

  return reservations.map(({ Instances }) => Instances ?? []).flat()
}

async function start(instances: Instance[]): Promise<InstanceStateChange[]> {
  const requests = instances.map(async ({ InstanceId, Placement }) =>
    new EC2Client({ region: Placement?.AvailabilityZone?.slice(0, -1) }).send(
      new StartInstancesCommand({ InstanceIds: [String(InstanceId)] })
    )
  )

  return (await Promise.all(requests))
    .map(({ StartingInstances }) => StartingInstances ?? [])
    .flat()
}

type WakeupOptions = {
  tags: Record<string, string>
  concurrency: number
  retries: number
}

type GroupedInstances = Record<string, Instance[]>

type InstanceCPUUsageLimits = {
  max: number
  min: number
}

const TRANSIENT_ERRORS: Readonly<string[]> = [
  'IncorrectSpotRequestState',
  'InsufficientInstanceCapacity',
] as const

export default async function wakeup({
  tags,
  concurrency,
  retries,
}: WakeupOptions): Promise<InstanceStateChange[]> {
  const instances = await getInstances(tags)

  objectDebug('instances', instances)

  const {
    running = [],
    stopped = [],
    pending = [],
  } = instances.reduce((acc: GroupedInstances, instance: Instance): GroupedInstances => {
    const key = instance.State?.Name ?? 'unknown'

    if (Array.isArray(acc[key])) {
      acc[key].push(instance)
    } else {
      acc[key] = [instance]
    }

    return acc
  }, {})

  log.info(
    [
      'wakeup: instances found',
      `    running: ${running.length}`,
      `    stopped: ${stopped.length}`,
      `    pending: ${pending.length}`,
    ].join('\n')
  )

  const usage = await Promise.all(
    running.map(async (instance) => {
      const cw = new CloudWatchClient({
        region: instance.Placement?.AvailabilityZone?.slice(0, -1),
      })

      const { Datapoints = [] } = await cw.send(
        new GetMetricStatisticsCommand({
          Namespace: 'AWS/EC2',
          MetricName: 'CPUUtilization',
          Dimensions: [
            {
              Name: 'InstanceId',
              Value: String(instance.InstanceId),
            },
          ],
          Period: 60,
          StartTime: new Date(Date.now() - 60e3),
          EndTime: new Date(Date.now()),
          Statistics: ['Maximum'],
        })
      )

      objectDebug('DataPoints', { InstanceId: instance.InstanceId, Datapoints })

      // If there are no metrics for this given instance, assume it is idle with a 0% MAX usage, as
      // missing data probably means the instance just woke up from a long sleep.
      const instanceUsage: InstanceCPUUsageLimits = Datapoints.length
        ? Datapoints.reduce(
            (acc: InstanceCPUUsageLimits, point) => ({
              max: Math.max(acc.max, point.Maximum ?? acc.max),
              min: Math.min(acc.min, point.Maximum ?? acc.min),
            }),
            { min: Infinity, max: -Infinity }
          )
        : { min: 0, max: 0 }

      return {
        instance,
        ...instanceUsage,
      }
    })
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
    { busy: [], idle: [] }
  )

  if (running.length) {
    log.info(
      `wakeup: out of the ${running.length} running instances, ${busy.length} are busy and ${idle.length} are idle`
    )
  }

  const availableCount = idle.length + pending.length
  const deficitCount = Math.max(0, concurrency - availableCount)
  let startingInstances: InstanceStateChange[] = []

  if (!deficitCount) {
    log.info('wakeup: concurrency requirements met, nothing to do')
    return startingInstances
  }

  if (!stopped.length) {
    log.warn('wakeup: there are no more available runners, nothing to do')
    return startingInstances
  }

  const queueCount = Math.min(stopped.length, deficitCount)
  const toStartInstances = shuffle(stopped).slice(0, queueCount)

  log.info(
    [
      'wakeup: starting the following instances',
      ...toStartInstances.map(({ InstanceId }) => `    ${InstanceId}`),
    ].join('\n')
  )

  try {
    startingInstances = await start(toStartInstances)
  } catch (err: unknown) {
    if (isObject(err)) {
      if (TRANSIENT_ERRORS.includes(err.Code as string)) {
        if (retries) {
          log.warn(`wakeup: some spot instances are not ready, retrying in 10sec...`)
          await wait(10000)
          return wakeup({ tags, concurrency, retries: retries - 1 })
        }

        log.error(`wakeup: Couldn't get spot instances to cover desired concurrency capacity`)
      }
    }

    throw err
  }

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
