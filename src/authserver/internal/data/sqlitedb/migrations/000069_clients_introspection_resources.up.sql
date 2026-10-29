-- A client's introspection resources (#676 decisions 5 and 14): the resources whose tokens a
-- confidential client may introspect. Goiabada's APIs are resources, which hold no credentials, so
-- an API introspects as a confidential client, and this table is what links the client to the
-- resources it stands for. One client may stand for several resources and several clients for one.
-- Every list starts empty, so no client introspects until an administrator allows it.
--
-- The six questions (reference/migrations.md 6): (1) all four engines. (2) No string column, so no
-- collation is pinned on a column. (3) The lookups compare ids. (4) A client lists a resource once:
-- the pair is unique, and a list save that overlaps another meets the key as the 409 every list
-- save answers. (5) No existing row changes meaning, and nothing is backfilled: before this
-- migration no client could introspect. (6) Each schema.golden gains the table.
--
-- Both foreign keys cascade, so deleting a client or a resource removes its links. The unique
-- index leads with client_id and serves the client's list; the resource's own index serves the
-- cascade from resources.
CREATE TABLE clients_introspection_resources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at DATETIME NULL,
    client_id INTEGER NOT NULL,
    resource_id INTEGER NOT NULL,
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE,
    FOREIGN KEY (resource_id) REFERENCES resources(id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX idx_clients_introspection_resources_client_resource ON clients_introspection_resources(client_id, resource_id);
CREATE INDEX idx_clients_introspection_resources_resource_id ON clients_introspection_resources(resource_id);
