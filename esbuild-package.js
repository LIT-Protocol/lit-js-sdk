const { build } = require('esbuild')
build({
  entryPoints: ['src/index.js'],
  bundle: false,
  minify: true,
  sourcemap: true,
  outfile: 'build/index.js',
  sourceRoot: './'
})
