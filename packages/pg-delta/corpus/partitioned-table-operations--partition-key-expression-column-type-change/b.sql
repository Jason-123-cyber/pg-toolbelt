-- varchar(64), not text: both sides deparse the key as lower((region)::text),
-- so partitionKey is unchanged and only the key-column detection replaces the
-- table. A text target would change the deparse and replace it anyway.
CREATE SCHEMA test_schema;

CREATE TABLE test_schema.accounts (region varchar(64)) PARTITION BY LIST (lower(region));
