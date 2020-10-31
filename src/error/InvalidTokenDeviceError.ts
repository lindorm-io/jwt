import { ExtendableError } from "@lindorm-io/core";

export class InvalidTokenDeviceError extends ExtendableError {
  constructor(expect: string, actual: string) {
    super("Client ID is invalid", {
      debug: { expect, actual },
    });
  }
}
