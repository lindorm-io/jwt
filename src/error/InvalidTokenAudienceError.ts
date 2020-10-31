import { ExtendableError } from "@lindorm-io/core";
import { NotBeforeError } from "jsonwebtoken";

export class InvalidTokenAudienceError extends ExtendableError {
  constructor(error: NotBeforeError, audience: string) {
    super("Token audience is invalid", {
      debug: { audience, error },
    });
  }
}