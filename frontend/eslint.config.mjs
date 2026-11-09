import tseslint from 'typescript-eslint';

export default [
  { ignores: ['dist/**', '.test-build/**'] },
  ...tseslint.configs.recommended,
];
