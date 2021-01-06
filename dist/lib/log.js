"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.objectDebug = void 0;
const loglevel_1 = __importDefault(require("loglevel"));
if (process.env.LOG_LEVEL) {
    loglevel_1.default.setLevel(process.env.LOG_LEVEL);
}
const objectDebug = (name, content) => {
    const paddedContent = JSON.stringify(content, null, 2)
        .split('\n')
        .map((line) => `    ${line}`)
        .join('\n');
    loglevel_1.default.debug([`wakeup: ${name} contents`, paddedContent].join('\n'));
};
exports.objectDebug = objectDebug;
exports.default = loglevel_1.default;
