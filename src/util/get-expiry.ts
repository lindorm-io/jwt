import { DateError } from "../error";
import { Expiry } from "../typing";
import { add, getUnixTime, isBefore, isDate } from "date-fns";
import { isNumber, isString } from "lodash";
import { stringToDurationObject } from "@lindorm-io/core";

const secondsToDate = (seconds: number): Date => {
  return new Date(seconds * 1000);
};

const stringToDate = (string: string): Date => {
  return add(Date.now(), stringToDurationObject(string));
};

const assertSeconds = (number: number): void => {
  if (number > 9999999999) {
    throw new DateError("Invalid expiry", {
      debug: { date: new Date(number), number },
      description: "Expiry is not in seconds",
    });
  }
};

const assertExpiryDate = (date: Date): void => {
  const now = new Date();

  if (isBefore(date, now)) {
    throw new DateError("Invalid expiry", {
      debug: { date, now },
      description: "Expiry is before current date",
    });
  }
};

const convertExpiryToDate = (expiry: Expiry): Date => {
  if (isString(expiry)) {
    return stringToDate(expiry);
  }
  if (isNumber(expiry)) {
    assertSeconds(expiry);

    return secondsToDate(expiry);
  }
  if (isDate(expiry)) {
    return expiry;
  }

  throw new DateError("Invalid expiry", {
    debug: { expiry },
    description: "Expiry is not [ string | number | Date ]",
  });
};

export const getExpiry = (expiry: Expiry): number => {
  const date = convertExpiryToDate(expiry);

  assertExpiryDate(date);

  return getUnixTime(date);
};
