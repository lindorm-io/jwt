import { ExtendableError } from "@lindorm-io/errors";

export class DecodeTokenError extends ExtendableError {
  public constructor(error: Error) {
    super("Token can not be decoded", {
      debug: { error },
    });
  }
}
