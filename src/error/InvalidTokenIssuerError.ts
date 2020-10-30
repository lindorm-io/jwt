import { ExtendableError } from "@lindorm-io/global";
import { NotBeforeError } from "jsonwebtoken";

export class InvalidTokenIssuerError extends ExtendableError {
  constructor(error: NotBeforeError, issuer: string) {
    super("Token issuer is invalid", {
      debug: { error, issuer },
    });
  }
}
