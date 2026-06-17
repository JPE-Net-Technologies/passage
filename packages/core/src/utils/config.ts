// utils/config.ts
// Environment detection for @passage/core.
//
// Config *loading* (reading YAML off disk) deliberately does NOT live here: a library
// must not assume the consumer's working directory holds a `config/` dir. Consumers
// inject a validated `AppConfig` into `createApp()` (see `../app`), and the optional
// `@passage/core/config` subpath (`../config-loader`) provides a directory-parameterized
// loader for presets that want it.
export const ENV: "production" | "development" =
    process.env.NODE_ENV === "development" ? 'development' : 'production';
