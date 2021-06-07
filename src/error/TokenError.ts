import { ExtendableError, ExtendableErrorOptions } from "@lindorm-io/errors";

export class TokenError extends ExtendableError {
  public constructor(message: string, options?: ExtendableErrorOptions) {
    super(message, options);
  }
}
