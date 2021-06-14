import MockDate from "mockdate";
import { getExpiry } from "./get-expiry";
import { DateError } from "../error";

MockDate.set("2021-01-01T08:00:00.000Z");

describe("getExpiry", () => {
  test("should convert string to expiry", () => {
    expect(getExpiry("10 minutes")).toBe(1609488600);
  });

  test("should convert number to expiry", () => {
    expect(getExpiry(1609488600)).toBe(1609488600);
  });

  test("should convert date to expiry", () => {
    expect(getExpiry(new Date("2021-01-01T08:10:00.000Z"))).toBe(1609488600);
  });

  test("should throw when expiry is invalid type", () => {
    // @ts-ignore
    expect(() => getExpiry(true)).toThrow(DateError);
  });

  test("should throw when number expiry is not in seconds", () => {
    expect(() => getExpiry(10000000000)).toThrow(DateError);
  });

  test("should throw when expiry is before current date", () => {
    expect(() => getExpiry(new Date("1999-01-01T08:00:00.000Z"))).toThrow(DateError);
  });
});
