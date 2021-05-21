const { build } = require('esbuild')
build({
  entryPoints: ['src/index.js'],
  bundle: true,
  // minify: true,
  sourcemap: true,
  outfile: 'build/index.web.js',
  sourceRoot: './',
  globalName: 'LitJsSdk',
  define: {
    global: 'window',
  },
  inject: ['polyfills.js']
})
