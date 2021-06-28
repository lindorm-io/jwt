import { Keystore } from "@lindorm-io/key-pair";
import { Logger } from "@lindorm-io/winston";

export interface IssuerOptions {
  issuer: string;
  keystore: Keystore;
  logger: Logger;
}
