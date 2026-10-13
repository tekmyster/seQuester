CREATE TABLE dbo.endpoint_contact(endpoint char(32) NOT NULL PRIMARY KEY REFERENCES dbo.endpoints(id),address nvarchar(64) NOT NULL,observed bigint NOT NULL);
