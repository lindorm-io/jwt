import { includes } from "lodash";
import { Scope } from "../enum";

export const isValidScope = (scope: string): boolean => {
  const split = scope.split(" ");

  for (const item of split) {
    if (includes(Scope, item)) continue;
    return false;
  }

  return true;
};

export const isScope = (scope: string, expectedScope: Scope): boolean => {
  const split = scope.split(" ");

  for (const item of split) {
    if (item !== expectedScope) continue;
    return true;
  }

  return false;
};
