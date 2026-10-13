CREATE TABLE dbo.tokens(id varchar(48) COLLATE Latin1_General_100_BIN2 NOT NULL PRIMARY KEY,name nvarchar(160) NOT NULL,type varchar(64) COLLATE Latin1_General_100_BIN2 NOT NULL,created bigint NOT NULL,revoked bigint NOT NULL DEFAULT 0);
CREATE TABLE dbo.token_options(id varchar(48) COLLATE Latin1_General_100_BIN2 NOT NULL PRIMARY KEY,destination nvarchar(2048) NOT NULL);
