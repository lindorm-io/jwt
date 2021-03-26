import { includes } from "lodash";
import { Scope } from "../enum";

export const isValidScope = (scope: Array<string>): boolean => {
  if (!scope) return false;

  for (const item of scope) {
    if (includes(Scope, item)) continue;
    return false;
  }

  return true;
};

export const isScope = (scope: Array<string>, expectedScope: Scope): boolean => {
  if (!scope) return false;

  for (const item of scope) {
    if (item !== expectedScope) continue;
    return true;
  }

  return false;
};
