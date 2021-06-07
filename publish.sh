#!/bin/zsh

yarn build
yarn buildWeb
yarn publish

echo "Don't forget to git push to get this running on the netlify cdn"