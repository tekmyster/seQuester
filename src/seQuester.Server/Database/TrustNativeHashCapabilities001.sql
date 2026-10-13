CREATE TABLE dbo.trust_native_hash_capabilities(endpoint varchar(32) COLLATE Latin1_General_100_BIN2 NOT NULL PRIMARY KEY REFERENCES dbo.endpoints(id),version int NOT NULL,reported bigint NOT NULL);
