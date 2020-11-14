import { isScope } from "./is-scope";
import { Scope } from "../enum";

describe("isScope", () => {
  test("should resolve true when scope exists", () => {
    expect(isScope("default edit", Scope.EDIT)).toBe(true);
  });

  test("should resolve false when scope is missing", () => {
    expect(isScope("default edit", Scope.BIRTH_DATE)).toBe(false);
  });

  test("should resolve only on specific scopes", () => {
    expect(isScope("defaultedt", Scope.DEFAULT)).toBe(false);
  });
});
