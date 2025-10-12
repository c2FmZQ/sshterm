import resolve from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';
import babel from '@rollup/plugin-babel';

export default {
  input: 'browser.js',
  output: {
    file: '../docroot/xterm.mjs',
    format: 'es',
    sourcemap: false,
  },
  plugins: [
    resolve(),
    commonjs(),
    babel({
      babelHelpers: 'bundled',
      presets: ['@babel/preset-env'],
      exclude: 'node_modules/**',
    }),
  ],
};
