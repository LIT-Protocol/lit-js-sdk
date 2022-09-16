#!/bin/zsh

yarn versionBump
RESULT=$(cat src/version.js | grep -E -o "'.*'")
VERSION="${RESULT:1:${#RESULT}-2}" # strip the 's at the beginning and end
BRANCH=$(git rev-parse --abbrev-ref HEAD)

./gen_docs.sh

yarn build
yarn buildWeb
yarn buildNode

case $BRANCH in
  "main")
    yarn publish --new-version $VERSION
    ;;

  "serrano")
    yarn publish --new-version $VERSION --tag serrano
    ;;

  *)
    echo -n "Invalid branch.  Only main and serrano supported for publishing."
    exit
    ;;
esac


./create_subpackage_packagejson.sh

# copy the nodejs build
cp build/index.node.js packages/sdk-nodejs/build/
cd packages/sdk-nodejs
case $BRANCH in
  "main")
    yarn publish --new-version $VERSION --no-git-tag-version
    ;;

  "serrano")
    yarn publish --new-version $VERSION --no-git-tag-version --tag serrano
    ;;

  *)
    echo -n "Invalid branch.  Only main and serrano supported for publishing."
    exit
    ;;
esac
cd ../..


# copy the browser build
cp build/index.js packages/sdk-browser/build/
cd packages/sdk-browser
case $BRANCH in
  "main")
    yarn publish --new-version $VERSION --no-git-tag-version
    ;;

  "serrano")
    yarn publish --new-version $VERSION --no-git-tag-version --tag serrano
    ;;

  *)
    echo -n "Invalid branch.  Only main and serrano supported for publishing."
    exit
    ;;
esac

cd ../..

# copy the browser-standalone build
cp build/index.web.js packages/sdk-browser-standalone/build/
cd packages/sdk-browser-standalone
case $BRANCH in
  "main")
    yarn publish --new-version $VERSION --no-git-tag-version
    ;;

  "serrano")
    yarn publish --new-version $VERSION --no-git-tag-version --tag serrano
    ;;

  *)
    echo -n "Invalid branch.  Only main and serrano supported for publishing."
    exit
    ;;
esac



echo "Don't forget to git push to get this running on the netlify cdn"