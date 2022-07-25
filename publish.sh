#!/bin/zsh

yarn versionBump
RESULT=$(cat src/version.js | grep -E -o "'.*'")
VERSION="${RESULT:1:${#RESULT}-2}" # strip the 's at the beginning and end

./gen_docs.sh

yarn build
yarn buildWeb
yarn buildNode

yarn publish --new-version $VERSION

# copy the nodejs build
cp build/index.node.js packages/sdk-nodejs/build/
# don't copy the source map because it's huge, like 4.5MB.  
# cp build/index.node.js.map packages/sdk-nodejs/build/
cd packages/sdk-nodejs
yarn publish --new-version $VERSION

echo "Don't forget to git push to get this running on the netlify cdn"