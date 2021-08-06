const { build } = require('esbuild')
build({
  entryPoints: ['tests/provisioningAndSigning.js'],
  bundle: true,
  minify: true,
  sourcemap: true,
  outfile: 'build/tests.js',
  sourceRoot: './',
  format: 'cjs',
  inject: ['./node_modules/node-fetch-polyfill/index.js'],
})
