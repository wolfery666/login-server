-- +goose Up
-- +goose StatementBegin
CREATE TABLE "tokens" (
  "token" character varying(36) NOT NULL,
  "login" character varying(20) NOT NULL,
  "expiration" TIMESTAMP NOT NULL,
  PRIMARY KEY ("token")
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE "tokens";
-- +goose StatementEnd
