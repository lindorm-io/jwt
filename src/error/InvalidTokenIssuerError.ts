import { ExtendableError } from "@lindorm-io/errors";
import { NotBeforeError } from "jsonwebtoken";

export class InvalidTokenIssuerError extends ExtendableError {
  constructor(error: NotBeforeError, issuer: string) {
    super("Token issuer is invalid", {
      debug: { error, issuer },
    });
  }
}
