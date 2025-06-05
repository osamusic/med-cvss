module.exports = {
  parser: '@typescript-eslint/parser',
  parserOptions: {
    ecmaVersion: 2020,
    sourceType: 'module',
    ecmaFeatures: {
      jsx: true,
    },
  },
  plugins: ['@typescript-eslint', 'react', 'react-hooks', 'prettier'],
  extends: [
    'react-app',
    'react-app/jest',
    'prettier',
    'plugin:prettier/recommended',
  ],
  rules: {
    // Prettier integration
    'prettier/prettier': 'error',
    
    // React specific rules
    'react-hooks/rules-of-hooks': 'error',
    'react-hooks/exhaustive-deps': 'warn',
    'react/prop-types': 'off', // TypeScript handles this
    'react/react-in-jsx-scope': 'off', // Not needed in React 17+
    
    // General code quality
    'no-console': 'warn',
    'no-debugger': 'error',
    'prefer-const': 'error',
    'no-var': 'error',
    
    // Medical device specific - ensure error handling
    'no-throw-literal': 'error',
    'no-implicit-coercion': 'error',
    
    // Security considerations for medical apps
    'no-eval': 'error',
    'no-implied-eval': 'error',
    'no-script-url': 'error',
  },
  env: {
    browser: true,
    es6: true,
    jest: true,
    node: true,
  },
  settings: {
    react: {
      version: 'detect',
    },
  },
  overrides: [
    {
      files: ['**/__tests__/**/*', '**/*.test.*'],
      rules: {
        // Allow console in tests
        'no-console': 'off',
        // Allow any types in test files for mocking
        '@typescript-eslint/no-explicit-any': 'off',
      },
    },
  ],
};