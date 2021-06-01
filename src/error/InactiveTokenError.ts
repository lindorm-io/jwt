import { ExtendableError } from "@lindorm-io/errors";
import { NotBeforeError } from "jsonwebtoken";

export class InactiveTokenError extends ExtendableError {
  public constructor(error: NotBeforeError) {
    super(`Token is inactive and can not be used until [ ${error.date} ]`, {
      debug: { error },
    });
  }
}
