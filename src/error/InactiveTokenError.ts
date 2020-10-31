import { ExtendableError } from "@lindorm-io/core";
import { NotBeforeError } from "jsonwebtoken";

export class InactiveTokenError extends ExtendableError {
  constructor(error: NotBeforeError) {
    super(`Token is inactive and can not be used until [ ${error.date} ]`, {
      debug: { error },
    });
  }
}