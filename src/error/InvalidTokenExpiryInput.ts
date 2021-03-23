import { ExtendableError } from "@lindorm-io/errors";

export class InvalidTokenExpiryInput extends ExtendableError {
  constructor(expiry: any) {
    super("Expiry input is invalid", {
      debug: { expiry },
    });
  }
}
