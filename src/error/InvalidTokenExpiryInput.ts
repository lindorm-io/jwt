import { ExtendableError } from "@lindorm-io/global";

export class InvalidTokenExpiryInput extends ExtendableError {
  constructor(expiry: any) {
    super("Expiry input is invalid", {
      debug: { expiry },
    });
  }
}
