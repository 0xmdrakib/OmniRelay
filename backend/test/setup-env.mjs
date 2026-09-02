// Unit tests exercise configuration-dependent modules without opening a real
// database connection. CI integration tests provide their own ephemeral URL.
process.env.NODE_ENV ??= "test";
process.env.DATABASE_URL ??= "postgres://test:test@127.0.0.1:5432/omnirelay_test";
