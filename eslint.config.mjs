// ESLint flat config — https://eslint.org/docs/latest/use/configure/configuration-files
import js from '@eslint/js';
import globals from 'globals';

export default [
  {
    ignores: [
      'node_modules/**',
      '.vercel/**',
      'dist/**',
      'build/**',
      'coverage/**',
      // Skip the monolithic HTML — it's not a JS module.
      'index.html',
    ],
  },

  js.configs.recommended,

  // Serverless API — Node ESM
  {
    files: ['api/**/*.{js,mjs}'],
    languageOptions: {
      ecmaVersion: 2023,
      sourceType: 'module',
      globals: { ...globals.node },
    },
    rules: {
      'no-console': ['warn', { allow: ['warn', 'error'] }],
      'no-unused-vars': ['warn', { argsIgnorePattern: '^_' }],
    },
  },

  // Tests
  {
    files: ['tests/**/*.{js,mjs}'],
    languageOptions: {
      ecmaVersion: 2023,
      sourceType: 'module',
      globals: { ...globals.node },
    },
    rules: {
      'no-unused-vars': ['warn', { argsIgnorePattern: '^_' }],
    },
  },

  // Build / dev scripts
  {
    files: ['scripts/**/*.{js,mjs}'],
    languageOptions: {
      ecmaVersion: 2023,
      sourceType: 'module',
      globals: { ...globals.node },
    },
    rules: {
      'no-console': 'off',
    },
  },

  // Service worker — browser global scope
  {
    files: ['sw.js'],
    languageOptions: {
      ecmaVersion: 2023,
      sourceType: 'script',
      globals: { ...globals.serviceworker, ...globals.browser },
    },
  },
];
