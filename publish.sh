#!/bin/zsh

yarn versionBump
RESULT=$(cat src/version.js | grep -E -o "'.*'")
VERSION="${RESULT:1:${#RESULT}-2}" # strip the 's at the beginning and end

./gen_docs.sh

yarn build
yarn buildWeb
yarn buildNode

yarn publish --new-version $VERSION

./create_subpackage_packagejson.sh

# copy the nodejs build
cp build/index.node.js packages/sdk-nodejs/build/
cd packages/sdk-nodejs
yarn publish --new-version $VERSION --no-git-tag-version

cd ../..


# copy the browser build
cp build/index.js packages/sdk-browser/build/
cd packages/sdk-browser
yarn publish --new-version $VERSION --no-git-tag-version

cd ../..

# copy the browser-standalone build
cp build/index.web.js packages/sdk-browser-standalone/build/
cd packages/sdk-browser-standalone
yarn publish --new-version $VERSION --no-git-tag-version


echo "Don't forget to git push to get this running on the netlify cdn"