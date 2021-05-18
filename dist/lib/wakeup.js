"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const aws_sdk_1 = __importDefault(require("aws-sdk"));
const log_1 = __importStar(require("./log"));
const cw = new aws_sdk_1.default.CloudWatch({ apiVersion: '2010-08-01' });
const ec2 = new aws_sdk_1.default.EC2({ apiVersion: '2016-11-15' });
function swap(arr, i, j) {
    [arr[i], arr[j]] = [arr[j], arr[i]];
    return arr;
}
function shuffle(arr) {
    const copy = arr.slice();
    for (let i = 0; i < copy.length; i++) {
        const j = Math.floor(Math.random() * (i + 1));
        swap(copy, i, j);
    }
    return copy;
}
function wait(ms, x) {
    return new Promise((resolve) => setTimeout(() => resolve(x), ms));
}
async function getInstances(tags) {
    const Filters = Object.entries(tags).map(([key, val]) => ({
        Name: `tag:${key}`,
        Values: val.split(','),
    }));
    log_1.objectDebug('filters', Filters);
    // AWS SDK throws if Filters is an empty array or empty object is set as options.
    const { Reservations } = Filters.length
        ? await ec2.describeInstances({ Filters }).promise()
        : await ec2.describeInstances().promise();
    if (Reservations === undefined) {
        return [];
    }
    log_1.objectDebug('Reservations', Reservations);
    return Reservations.map(({ Instances }) => Instances !== null && Instances !== void 0 ? Instances : []).flat();
}
async function start(instances) {
    const InstanceIds = instances.map((instance) => instance.InstanceId);
    const { StartingInstances } = await ec2.startInstances({ InstanceIds }).promise();
    return StartingInstances !== null && StartingInstances !== void 0 ? StartingInstances : [];
}
async function wakeup({ tags, concurrency }, retries = 5) {
    var _a;
    const instances = await getInstances(tags);
    log_1.objectDebug('instances', instances);
    const { running = [], stopped = [], pending = [], } = instances.reduce((acc, instance) => {
        var _a, _b;
        const key = (_b = (_a = instance === null || instance === void 0 ? void 0 : instance.State) === null || _a === void 0 ? void 0 : _a.Name) !== null && _b !== void 0 ? _b : 'unknown';
        if (acc[key]) {
            acc[key].push(instance);
        }
        else {
            acc[key] = [instance];
        }
        return acc;
    }, {});
    log_1.default.info([
        'wakeup: instances found',
        `    running: ${running.length}`,
        `    stopped: ${stopped.length}`,
        `    pending: ${pending.length}`,
    ].join('\n'));
    const usage = await Promise.all(running.map((instance) => cw
        .getMetricStatistics({
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
    }, undefined)
        .promise()
        .then(({ Datapoints = [] }) => {
        log_1.objectDebug('DataPoints', Datapoints);
        const instanceUsage = Datapoints.length
            ? Datapoints.reduce((acc, point) => {
                var _a, _b;
                return ({
                    max: Math.max(acc.max, (_a = point.Maximum) !== null && _a !== void 0 ? _a : acc.max),
                    min: Math.min(acc.min, (_b = point.Maximum) !== null && _b !== void 0 ? _b : acc.min),
                });
            }, { min: Infinity, max: -Infinity })
            : { min: 0, max: 100 };
        return {
            instance,
            ...instanceUsage,
        };
    })));
    const { busy, idle } = usage.reduce((acc, { instance, max }) => {
        if (max > 10) {
            acc.busy.push(instance);
        }
        else {
            acc.idle.push(instance);
        }
        return acc;
    }, { busy: [], idle: [] });
    if (running.length) {
        log_1.default.info(`wakeup: out of the running instances, ${busy.length} are busy and ${idle.length} are idle`);
    }
    const availableCount = idle.length + pending.length;
    const deficitCount = Math.max(0, concurrency - availableCount);
    if (!deficitCount) {
        log_1.default.info('wakeup: concurrency requirements met, nothing to do');
        return [];
    }
    if (!stopped.length) {
        log_1.default.warn('wakeup: there are no more available runners, nothing to do');
        return [];
    }
    const queueCount = Math.min(stopped.length, deficitCount);
    const toStartInstances = shuffle(stopped).slice(0, queueCount);
    log_1.default.info([
        'wakeup: starting the following instances',
        ...toStartInstances.map(({ InstanceId }) => `    ${InstanceId}`),
    ].join('\n'));
    let startingInstances = [];
    try {
        startingInstances = (_a = (await start(toStartInstances))) !== null && _a !== void 0 ? _a : [];
    }
    catch (err) {
        if (err.code === 'IncorrectSpotRequestState') {
            if (retries) {
                log_1.default.warn(`wakeup: some spot instances are not ready, retrying in 3sec...`);
                await wait(3000);
                return wakeup({ tags, concurrency }, retries - 1);
            }
            log_1.default.error(`wakeup: Couldn't get spot instances to start`);
            throw err;
        }
        throw err;
    }
    log_1.default.info([
        'wakeup: request sent',
        ...startingInstances.map(({ CurrentState, InstanceId }) => { var _a; return `    ${InstanceId}: ${(_a = CurrentState === null || CurrentState === void 0 ? void 0 : CurrentState.Name) !== null && _a !== void 0 ? _a : 'unknown'}`; }),
    ].join('\n'));
    return startingInstances;
}
exports.default = wakeup;
