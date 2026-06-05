import { defineConfig } from "orval";

// Generates a fully-typed TanStack Query client from the control-plane
// OpenAPI document (`api/openapi.yaml` at the repo root). The generated
// code lands in `src/api/generated/` and is committed so the build does
// not depend on regeneration; run `npm run gen:api` to refresh it after
// the spec changes.
export default defineConfig({
  sng: {
    input: {
      target: "../api/openapi.yaml",
    },
    output: {
      mode: "tags-split",
      target: "./src/api/generated/endpoints",
      schemas: "./src/api/generated/model",
      client: "react-query",
      httpClient: "axios",
      clean: true,
      prettier: false,
      override: {
        mutator: {
          path: "./src/api/http-client.ts",
          name: "sngRequest",
        },
        query: {
          useQuery: true,
          useInfinite: false,
        },
      },
    },
    hooks: {},
  },
});
