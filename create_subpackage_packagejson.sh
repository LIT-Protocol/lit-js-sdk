#!/bin/bash


DEPS="$(cat package.json | jq .dependencies)"
DEV_DEPS="$(cat package.json | jq .devDependencies)"

cat packages/sdk-browser/package.json.template | jq ".dependencies|=$DEPS | .devDependencies|=$DEV_DEPS" > packages/sdk-browser/package.json

cat packages/sdk-browser-standalone/package.json.template | jq ".dependencies|=$DEPS | .devDependencies|=$DEV_DEPS" > packages/sdk-browser-standalone/package.json

cat packages/sdk-nodejs/package.json.template | jq ".dependencies|=$DEPS | .devDependencies|=$DEV_DEPS" > packages/sdk-nodejs/package.json
