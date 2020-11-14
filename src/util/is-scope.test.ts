import { Scope } from "../enum";
import { isScope, isValidScope } from "./is-scope";

describe("isValidScope", () => {
  test("should resolve true when scope is valid", () => {
    expect(isValidScope("default edit birth_date")).toBe(true);
  });

  test("should resolve false when scope is not valid", () => {
    expect(isValidScope("defaultedit")).toBe(false);
  });
});

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
