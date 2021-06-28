import MockDate from "mockdate";
import { Keystore } from "@lindorm-io/key-pair";
import { TokenIssuer } from "./TokenIssuer";
import { baseParse } from "@lindorm-io/core";
import { getTestKeyPairEC, getTestKeyPairRSA, logger } from "../test";
import { TokenError } from "../error";
import { IssuerSignOptions } from "../typing";

const parseTokenData = (token: string): any => JSON.parse(baseParse(token.split(".")[1]));

MockDate.set("2021-01-01T08:00:00.000Z");

describe("TokenIssuer", () => {
  let handler: TokenIssuer;
  let issuer: any;
  let optionsMin: IssuerSignOptions<any, any>;
  let optionsFull: IssuerSignOptions<any, any>;

  beforeEach(() => {
    issuer = "issuer";
    optionsMin = {
      audience: ["audience"],
      expiry: "10 seconds",
      subject: "subject",
      type: "type",
    };
    optionsFull = {
      id: "d2457602-63bd-48c5-a19f-bfd81bf870c0",
      audience: ["audience"],
      authContextClass: ["acr"],
      authMethodsReference: ["amr"],
      claims: { claimsKey: "claimValue" },
      expiry: "10 seconds",
      nonce: "bed190d568a5456bb15a39cf71d72022",
      notBefore: new Date(),
      payload: { payloadKey: "payloadValue" },
      permission: "permission",
      scopes: ["scope"],
      subject: "subject",
      type: "type",
      username: "username",
    };
    handler = new TokenIssuer({
      issuer,
      keystore: new Keystore({ keys: [getTestKeyPairEC()] }),
      logger,
    });
  });

  afterEach(jest.clearAllMocks);

  describe("RS512", () => {
    beforeEach(() => {
      handler = new TokenIssuer({
        issuer,
        keystore: new Keystore({ keys: [getTestKeyPairRSA()] }),
        logger,
      });
    });

    test("should sign/verify", () => {
      const { id, token } = handler.sign(optionsMin);

      expect(handler.verify(token)).toStrictEqual(
        expect.objectContaining({
          id,
          token,
          audience: ["audience"],
          subject: "subject",
          type: "type",
        }),
      );
    });
  });

  describe("ES512", () => {
    beforeEach(() => {
      handler = new TokenIssuer({
        issuer,
        keystore: new Keystore({ keys: [getTestKeyPairEC()] }),
        logger,
      });
    });

    test("should sign/verify", () => {
      const { id, token } = handler.sign(optionsMin);

      expect(handler.verify(token)).toStrictEqual(
        expect.objectContaining({
          id,
          token,
          audience: ["audience"],
          subject: "subject",
          type: "type",
        }),
      );
    });
  });

  test("should create", () => {
    expect(handler.sign(optionsMin)).toStrictEqual({
      id: expect.any(String),
      expires: expect.any(Date),
      expiresIn: 10,
      token: expect.any(String),
    });
  });

  test("should decode", () => {
    const { id, token } = handler.sign(optionsFull);

    expect(TokenIssuer.decode(token)).toStrictEqual({
      id,
      audience: ["audience"],
      authContextClass: ["acr"],
      authMethodsReference: ["amr"],
      claims: { claimsKey: "claimValue" },
      keyId: "7531da89-12e9-403e-925a-5da49100635c",
      nonce: "bed190d568a5456bb15a39cf71d72022",
      payload: { payloadKey: "payloadValue" },
      permission: "permission",
      scopes: ["scope"],
      subject: "subject",
      type: "type",
      username: "username",
    });
  });

  test("should verify", () => {
    const { token } = handler.sign(optionsFull);

    expect(
      handler.verify(token, {
        audience: "audience",
        issuer: "issuer",
        maxAge: "90 minutes",
        nonce: "bed190d568a5456bb15a39cf71d72022",
        scopes: ["scope"],
        subject: "subject",
      }),
    ).toBeTruthy();
  });

  test("should return all signed values", () => {
    const { id, token } = handler.sign(optionsFull);

    expect(handler.verify(token)).toStrictEqual({
      id,
      audience: ["audience"],
      authContextClass: ["acr"],
      authMethodsReference: ["amr"],
      claims: { claimsKey: "claimValue" },
      nonce: "bed190d568a5456bb15a39cf71d72022",
      payload: { payloadKey: "payloadValue" },
      permission: "permission",
      scopes: ["scope"],
      subject: "subject",
      token: expect.any(String),
      type: "type",
      username: "username",
    });
  });

  test("should return default values", () => {
    const { id, token } = handler.sign(optionsMin);

    expect(handler.verify(token)).toStrictEqual({
      id: id,
      audience: ["audience"],
      authContextClass: [],
      authMethodsReference: [],
      claims: {},
      nonce: null,
      payload: {},
      permission: null,
      scopes: [],
      subject: "subject",
      token: token,
      type: "type",
      username: null,
    });
  });

  test("should store token claims in snake_case and decode to camelCase", () => {
    const { token } = handler.sign({
      ...optionsMin,
      claims: {
        caseOne: 1,
        caseTwo: "two",
        caseThree: { nestedOne: "one", nested_two: 2 },
        case_four: ["array", "data"],
        caseFive: true,
      },
    });

    const data = parseTokenData(token);

    expect(data).toStrictEqual(
      expect.objectContaining({
        case_five: true,
        case_four: ["array", "data"],
        case_one: 1,
        case_three: { nested_one: "one", nested_two: 2 },
        case_two: "two",
      }),
    );

    expect(handler.verify(token)).toStrictEqual(
      expect.objectContaining({
        claims: {
          caseFive: true,
          caseFour: ["array", "data"],
          caseOne: 1,
          caseThree: { nestedOne: "one", nestedTwo: 2 },
          caseTwo: "two",
        },
      }),
    );
  });

  test("should store token payload in snake_case and decode to camelCase", () => {
    const { token } = handler.sign({
      ...optionsMin,
      payload: {
        caseOne: 1,
        caseTwo: "two",
        caseThree: { nestedOne: "one", nested_two: 2 },
        case_four: ["array", "data"],
        caseFive: true,
      },
    });

    const data = parseTokenData(token);

    expect(data).toStrictEqual(
      expect.objectContaining({
        payload: {
          case_five: true,
          case_four: ["array", "data"],
          case_one: 1,
          case_three: { nested_one: "one", nested_two: 2 },
          case_two: "two",
        },
      }),
    );

    expect(handler.verify(token)).toStrictEqual(
      expect.objectContaining({
        payload: {
          caseFive: true,
          caseFour: ["array", "data"],
          caseOne: 1,
          caseThree: { nestedOne: "one", nestedTwo: 2 },
          caseTwo: "two",
        },
      }),
    );
  });

  test("should accept string as expiry", () => {
    const { token } = handler.sign({
      audience: optionsFull.audience,
      expiry: "10 seconds",
      subject: optionsFull.subject,
      type: "type",
    });

    const data = parseTokenData(token);

    expect(data).toStrictEqual(
      expect.objectContaining({
        exp: 1609488010,
        iat: 1609488000,
        nbf: 1609488000,
      }),
    );
  });

  test("should accept number as expiry", () => {
    const { token } = handler.sign({
      audience: optionsFull.audience,
      expiry: 1609488010,
      subject: optionsFull.subject,
      type: "type",
    });

    const data = parseTokenData(token);

    expect(data).toStrictEqual(
      expect.objectContaining({
        exp: 1609488010,
        iat: 1609488000,
        nbf: 1609488000,
      }),
    );
  });

  test("should accept Date as expiry", () => {
    const { token } = handler.sign({
      audience: optionsFull.audience,
      expiry: new Date("2021-12-12 12:00:00"),
      subject: optionsFull.subject,
      type: "type",
    });

    const data = parseTokenData(token);

    expect(data).toStrictEqual(
      expect.objectContaining({
        exp: 1639310400,
        iat: 1609488000,
        nbf: 1609488000,
      }),
    );
  });

  test("should reject missing scope", () => {
    const { token } = handler.sign({ ...optionsFull, scopes: [] });

    expect(() =>
      handler.verify(token, {
        scopes: ["unexpected"],
      }),
    ).toThrow(TokenError);
  });

  test("should reject invalid scope", () => {
    const { token } = handler.sign(optionsFull);

    expect(() =>
      handler.verify(token, {
        scopes: ["unexpected"],
      }),
    ).toThrow(TokenError);
  });

  test("should reject invalid type", () => {
    const { token } = handler.sign(optionsFull);

    expect(() =>
      handler.verify(token, {
        type: "wrong-type",
      }),
    ).toThrow(TokenError);
  });

  test("should reject expired", () => {
    const { token } = handler.sign({
      ...optionsFull,
      expiry: new Date("2021-01-01T08:10:00.000Z"),
    });

    MockDate.set("2022-01-01T08:10:00.000Z");

    expect(() => handler.verify(token)).toThrow(TokenError);

    MockDate.set("2021-01-01T08:00:00.000Z");
  });

  test("should reject token not yet valid", () => {
    const { token } = handler.sign({
      ...optionsFull,
      notBefore: new Date("2021-01-01T09:00:00.000Z"),
      expiry: new Date("2021-01-01T10:00:00.000Z"),
    });

    MockDate.set("2022-01-01T08:30:00.000Z");

    expect(() => handler.verify(token)).toThrow(TokenError);

    MockDate.set("2021-01-01T08:00:00.000Z");
  });
});
