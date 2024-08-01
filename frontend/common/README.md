# common

This library contains components relied on by both `web-interface` and `elgui`.

To keep Vite's hot-reload functionality happy, the dependency of those packages is not actually handled via pnpm, but rather via the `resolve.alias` option in `vite.config.ts` and the `compilerOptions.paths` option in `tsconfig.json` in both frontends. However, to keep Visual Studio Code's IntelliSense happy, this package has a `package.json` anyway.

To make references from this library to React work, you will need to run `pnpm install`.
