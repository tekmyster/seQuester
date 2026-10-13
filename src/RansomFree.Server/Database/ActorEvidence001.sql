CREATE TABLE dbo.actor_evidence(
 endpoint varchar(32) COLLATE Latin1_General_100_BIN2 NOT NULL REFERENCES dbo.endpoints(id), evidence_id varchar(32) COLLATE Latin1_General_100_BIN2 NOT NULL,
 completion_event varchar(32) COLLATE Latin1_General_100_BIN2 NOT NULL, receipt_id varchar(32) COLLATE Latin1_General_100_BIN2 NOT NULL, sha256 varchar(64) COLLATE Latin1_General_100_BIN2 NOT NULL,
 manifest_sha256 varchar(64) COLLATE Latin1_General_100_BIN2 NOT NULL,size bigint NOT NULL,manifest nvarchar(max) NOT NULL,
 state nvarchar(32) NOT NULL,created bigint NOT NULL,received bigint NULL,
 CONSTRAINT PK_actor_evidence PRIMARY KEY(endpoint,evidence_id),CONSTRAINT UQ_actor_evidence_event UNIQUE(endpoint,completion_event));
