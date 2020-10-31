import { ExtendableError } from "@lindorm-io/core";
import { TokenExpiredError } from "jsonwebtoken";

export class ExpiredTokenError extends ExtendableError {
  constructor(error: TokenExpiredError) {
    super("Token is expired", {
      debug: { error },
    });
  }
}
