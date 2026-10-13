CREATE TABLE dbo.decoy_services(id char(32) NOT NULL PRIMARY KEY,key_hash char(64) NOT NULL,payload nvarchar(max) NOT NULL);
CREATE TABLE dbo.decoy_service_versions(sequence bigint IDENTITY(1,1) NOT NULL PRIMARY KEY,id char(32) NOT NULL,revision bigint NOT NULL,actor nvarchar(256) NOT NULL,payload nvarchar(max) NOT NULL,CONSTRAINT UQ_decoy_service_version UNIQUE(id,revision));
CREATE TABLE dbo.decoy_service_hits(sequence bigint IDENTITY(1,1) NOT NULL PRIMARY KEY,id char(32) NOT NULL,observed bigint NOT NULL,address nvarchar(64) NOT NULL,method nvarchar(8) NOT NULL);
CREATE INDEX decoy_service_hit_order ON dbo.decoy_service_hits(id,sequence);
