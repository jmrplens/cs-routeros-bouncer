import js from "@eslint/js";
import astro from "eslint-plugin-astro";
import globals from "globals";
import tseslint from "typescript-eslint";

export default [
	{
		ignores: [".astro/**", "dist/**", "node_modules/**"],
	},
	js.configs.recommended,
	...tseslint.configs.recommended,
	...astro.configs["flat/recommended"],
	{
		files: ["**/*.{js,mjs,ts}"],
		languageOptions: {
			ecmaVersion: "latest",
			sourceType: "module",
			globals: {
				...globals.browser,
				...globals.nodeBuiltin,
			},
		},
	},
	{
		files: ["**/*.astro"],
		languageOptions: {
			parserOptions: {
				parser: tseslint.parser,
			},
		},
	},
];
