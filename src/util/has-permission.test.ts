import { isAdmin, isLocked, isUser } from "./has-permission";

describe("isAdmin", () => {
  test("should resolve true on ADMIN", () => {
    expect(isAdmin("admin")).toBe(true);
  });

  test("should resolve false on USER", () => {
    expect(isAdmin("user")).toBe(false);
  });

  test("should resolve false on LOCKED", () => {
    expect(isAdmin("locked")).toBe(false);
  });

  test("should resolve false on ANY", () => {
    expect(isAdmin("wrong")).toBe(false);
  });
});

describe("isUser", () => {
  test("should resolve false on ADMIN", () => {
    expect(isUser("admin")).toBe(false);
  });

  test("should resolve true on USER", () => {
    expect(isUser("user")).toBe(true);
  });

  test("should resolve false on LOCKED", () => {
    expect(isUser("locked")).toBe(false);
  });

  test("should resolve false on ANY", () => {
    expect(isUser("wrong")).toBe(false);
  });
});

describe("isLocked", () => {
  test("should resolve false on ADMIN", () => {
    expect(isLocked("admin")).toBe(false);
  });

  test("should resolve false on USER", () => {
    expect(isLocked("user")).toBe(false);
  });

  test("should resolve true on LOCKED", () => {
    expect(isLocked("locked")).toBe(true);
  });

  test("should resolve false on ANY", () => {
    expect(isLocked("wrong")).toBe(false);
  });
});
