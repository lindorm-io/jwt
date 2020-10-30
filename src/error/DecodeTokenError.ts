import { ExtendableError } from "@lindorm-io/global";

export class DecodeTokenError extends ExtendableError {
  constructor(error: Error) {
    super("Token can not be decoded", {
      debug: { error },
    });
  }
}
