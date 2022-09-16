"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.randomPath = void 0;
const randomPath = () => "/" + Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
exports.randomPath = randomPath;
