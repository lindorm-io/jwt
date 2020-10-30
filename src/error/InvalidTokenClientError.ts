import { ExtendableError } from "@lindorm-io/global";

export class InvalidTokenClientError extends ExtendableError {
  constructor(expect: string, actual: string) {
    super("Client ID is invalid", {
      debug: { expect, actual },
    });
  }
}
