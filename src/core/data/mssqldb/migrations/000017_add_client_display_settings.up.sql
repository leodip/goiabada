ALTER TABLE clients ADD display_name NVARCHAR(100) NOT NULL DEFAULT '';
ALTER TABLE clients ADD show_logo BIT NOT NULL DEFAULT 0;
ALTER TABLE clients ADD show_display_name BIT NOT NULL DEFAULT 0;
ALTER TABLE clients ADD show_description BIT NOT NULL DEFAULT 0;
ALTER TABLE clients ADD show_website_url BIT NOT NULL DEFAULT 0;
