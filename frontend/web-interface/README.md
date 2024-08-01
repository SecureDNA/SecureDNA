# web-interface

This is a [Vite](https://vitejs.dev/) + React web app that lets you play with the
[synthclient](../synthclient) API in a browser.

## Running it standalone

To spin it up, run `pnpm install`, then `pnpm dev`. Then go to
<http://localhost:5173/> in your browser. In the "SecureDNA API URL" field,
enter the URL of a [synthclient](../../crates/synthclient/README.md) instance.

Use `pnpm dev --port 12345` to configure the local port.

## Building a bundled component for the public demo

The public demo at <https://securedna.org/demo/> is powered by a bundle called
`visualization.es.js`, generated using a special Vite configuration of web-interface
(see [vite.config.component.ts](./vite.config.component.ts)).

To update this bundle, run `pnpm run build-component`, then copy
`dist/visualization.es.js` to
`website/frontend/src/components/blocks/visualization.es.js`.
