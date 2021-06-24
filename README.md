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
```

#### Sign
```typescript
const {
  id: tokenId,
  expiresIn,
  expires,
  token,
} = issuer.sign<Payload>({
  id,
  audience,
  authContextClass,
  authMethodsReference,
  clientId,
  deviceId,
  expiry,
  nonce,
  notBefore,
  payload,
  permission,
  scope,
  subject,
  type,
  username,
});
```

#### Verify
```typescript
const {
  id,
  audience,
  authContextClass,
  authMethodsReference,
  clientId,
  deviceId,
  nonce,
  payload,
  permission,
  scope,
  subject,
  token,
  type,
  username,
} = issuer.verify<Payload>(token, {
  audience,
  clientId,
  deviceId,
  issuer,
  nonce,
  subject,
  maxAge,
  type,
});
```

#### Decode
```typescript
const {
  keyId,
  claims,
} = TokenIssuer.decode(token);
```

#### Expiry
```typescript
TokenIssuer.getExpiry("10 seconds") // -> 1577865610
TokenIssuer.getExpiry(20) // -> 1577865610
TokenIssuer.getExpiry(new Date("2020-01-01T08:00:00.000Z")) // -> 1577865600

TokenIssuer.getUnixTime(new Date("2020-01-01T08:00:00.000Z")) // -> 1577865600

TokenIssuer.getExpiryDate(1577865600) // -> new Date("2020-01-01T08:00:00.000Z")
```

#### Sanitiser
```typescript
TokenIssuer.sanitiseToken(token) // -> <base64-header>.<base64-body>
```
