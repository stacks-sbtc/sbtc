// @ts-check

import eslint from "@eslint/js";
import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["tests/clarigen-types.ts"] },
  eslint.configs.recommended,
  ...tseslint.configs.recommended
);
