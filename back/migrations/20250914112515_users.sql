-- +goose Up
-- +goose StatementBegin
CREATE TABLE "users" (
  "login" character varying(20) NOT NULL,
  "encoded_hash" character varying(100) NOT NULL,
  PRIMARY KEY ("login")
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE "users";
-- +goose StatementEnd
