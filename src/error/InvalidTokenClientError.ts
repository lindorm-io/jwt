import { ExtendableError } from "@lindorm-io/errors";

export class InvalidTokenClientError extends ExtendableError {
  public constructor(expect: string, actual: string) {
    super("Client ID is invalid", {
      debug: { expect, actual },
    });
  }
}
