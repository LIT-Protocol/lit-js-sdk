#!/bin/zsh

yarn versionBump
RESULT=$(cat src/version.js | grep -E -o "'.*'")
VERSION="${RESULT:1:${#RESULT}-2}" # strip the 's at the beginning and end

yarn build
yarn buildWeb
yarn buildNode

yarn publish --new-version $VERSION

echo "Don't forget to git push to get this running on the netlify cdn"