CREATE TABLE dbo.trust_revisions(revision bigint IDENTITY(1,1) NOT NULL PRIMARY KEY,created bigint NOT NULL,actor nvarchar(256) NOT NULL,payload nvarchar(max) NOT NULL);
CREATE TABLE dbo.trust_current(id int NOT NULL PRIMARY KEY CHECK(id=1),revision bigint NOT NULL REFERENCES dbo.trust_revisions(revision));
CREATE TABLE dbo.trust_receipts(endpoint nvarchar(32) NOT NULL PRIMARY KEY,revision bigint NOT NULL,digest nvarchar(64) NOT NULL,group_id nvarchar(32) NULL,mode nvarchar(16) NOT NULL,reported bigint NOT NULL);
