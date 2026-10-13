CREATE TABLE dbo.endpoint_protection(
    endpoint varchar(32) COLLATE Latin1_General_100_BIN2 NOT NULL PRIMARY KEY REFERENCES dbo.endpoints(id),
    deployed_items int NOT NULL CHECK(deployed_items>=0 AND deployed_items<=100000),
    monitoring_state varchar(16) COLLATE Latin1_General_100_BIN2 NOT NULL CHECK(monitoring_state IN ('active','degraded','stopped','not-configured')),
    reported bigint NOT NULL
);
