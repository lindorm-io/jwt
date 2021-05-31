# @lindorm-io/jwt
JWT tools for lindorm.io packages.

## Installation
```shell script
npm install --save @lindorm-io/jwt
```

## Usage

### Token Issuer
```typescript
const issuer = new TokenIssuer({
  issuer: "https://authentication.service/",
  keystore: keyPairKeyStore,
  logger: winstonLogger,
});

const {
  id: tokenId,
  expiresIn,
  expires,
  level,
  token,
} = issuer.sign({
  audience: "access",
  expiry: "5 minutes",
  subject: "account_id",
  payload: { withData: "data" },
});

const {
  id,
  payload,
  subject,
} = issuer.verify({
  audience: "access",
  token,
  issuer: "https://authentication.service/",
});

TokenIssuer.dateToExpiry(new Date("2020-01-01T08:00:00.000Z")) // -> 1577865600
TokenIssuer.expiryToDate(1577865600) // -> new Date("2020-01-01T08:00:00.000Z")

TokenIssuer.getExpiry("10 seconds") // -> 1577865610
TokenIssuer.getExpiry(20) // -> 1577865610
TokenIssuer.getExpiry(new Date("2020-01-01T08:00:00.000Z")) // -> 1577865600
```

### Token Sanitiser
```typescript
sanitiseToken(token) // -> <base64-header>.<base64-body>
```
