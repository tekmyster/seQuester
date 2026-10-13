-- Additive management-only component. Receiver does not need this table.
CREATE TABLE dbo.token_details(
    id varchar(48) COLLATE Latin1_General_100_BIN2 NOT NULL PRIMARY KEY,
    location nvarchar(256) NOT NULL,
    description nvarchar(1000) NOT NULL,
    note nvarchar(2000) NOT NULL,
    email_alerts bigint NOT NULL,
    email_after bigint NOT NULL,
    CONSTRAINT CK_token_details_email CHECK(email_alerts IN (0,1)),
    CONSTRAINT CK_token_details_after CHECK(email_after>=0)
);
