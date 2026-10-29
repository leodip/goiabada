-- A client's introspection resources (#676 decisions 5 and 14). See the sqlite migration of the
-- same number for why, for the six questions and for what each index serves.
CREATE TABLE clients_introspection_resources (
    id BIGSERIAL PRIMARY KEY,
    created_at TIMESTAMP(6) NULL,
    client_id BIGINT NOT NULL,
    resource_id BIGINT NOT NULL,
    CONSTRAINT fk_clients_introspection_resources_client FOREIGN KEY (client_id) REFERENCES clients (id) ON DELETE CASCADE,
    CONSTRAINT fk_clients_introspection_resources_resource FOREIGN KEY (resource_id) REFERENCES resources (id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX idx_clients_introspection_resources_client_resource ON clients_introspection_resources(client_id, resource_id);
CREATE INDEX idx_clients_introspection_resources_resource_id ON clients_introspection_resources(resource_id);
