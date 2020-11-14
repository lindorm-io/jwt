import { Scope } from "../enum";

export const isScope = (scope: string, expectedScope: Scope): boolean => {
  const split = scope.split(" ");

  for (const item of split) {
    if (item === expectedScope) return true;
  }

  return false;
};
