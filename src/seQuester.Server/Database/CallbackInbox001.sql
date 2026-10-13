CREATE TABLE dbo.hits(sequence bigint IDENTITY(1,1) NOT NULL PRIMARY KEY,token varchar(48) COLLATE Latin1_General_100_BIN2 NOT NULL,received bigint NOT NULL,transport varchar(16) COLLATE Latin1_General_100_BIN2 NOT NULL,source varchar(64) COLLATE Latin1_General_100_BIN2 NOT NULL,detail nvarchar(256) NOT NULL);
CREATE INDEX hits_dedup ON dbo.hits(token,source,transport,received);
