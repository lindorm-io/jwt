import { ExtendableError } from "@lindorm-io/errors";

export class InvalidTokenExpiryInput extends ExtendableError {
  public constructor(expiry: any) {
    super("Expiry input is invalid", {
      debug: { expiry },
    });
  }
}
