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
    if (mod != null) for (var k in mod) if (k !== "default" && Object.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const core = __importStar(require("@actions/core"));
const aws_sdk_1 = __importDefault(require("aws-sdk"));
const log_1 = __importStar(require("./lib/log"));
async function run() {
    try {
        const options = {
            concurrency: Number.parseInt(core.getInput('concurrency') || '1', 10),
            tags: JSON.parse(core.getInput('tags') || '{}'),
            awsRegion: core.getInput('aws-region'),
        };
        log_1.objectDebug('options', options);
        if (options.awsRegion) {
            log_1.default.info(`wakeup: overrinding AWS Region to use ${options.awsRegion}`);
            aws_sdk_1.default.config.update({ region: options.awsRegion });
        }
        const { default: wakeup } = await Promise.resolve().then(() => __importStar(require('./lib/wakeup')));
        await wakeup(options);
    }
    catch (error) {
        console.trace(error);
        core.setFailed(error.message);
    }
}
run();
