CREATE TABLE dbo.service_evidence(sequence bigint IDENTITY(1,1) NOT NULL PRIMARY KEY,event_id char(32) NOT NULL UNIQUE,received bigint NOT NULL,payload nvarchar(max) NOT NULL);
