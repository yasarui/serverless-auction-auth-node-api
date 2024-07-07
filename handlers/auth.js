const jwt = require('jsonwebtoken');
const createError = require('http-errors');
const path = require('path');
const fs = require('fs');
const pemFile = path.resolve(__dirname, '../secret.pem');
const cert = fs.readFileSync(pemFile);

const generatePolicy = (principalId, methodArn) => {
    const apiGatewayWildcard = methodArn.split('/', 2).join('/') + '/*';
  
    return {
      principalId,
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Allow',
            Resource: apiGatewayWildcard,
          },
        ],
      },
    };
  };

exports.handler = async (event) => {
  if (event.type === "TOKEN") {
    if (!event.authorizationToken) {
      throw createError.Unauthorized();
    }
    const token =
      event.authorizationToken.replace("Bearer ", "") ||
      event.headers.authorization.replace("Bearer ", "");
    try {
      const claims = jwt.verify(token, cert);
      const policy = generatePolicy(claims.sub, event.methodArn);
      return {
        ...policy,
        context: claims,
      };
    } catch (error) {
      throw createError.Unauthorized();
    }
  } else if (event.type === "REQUEST") {
    if (!event.headers.authorization) {
      throw createError.Unauthorized();
    }
    const token = event.headers.authorization.replace("Bearer ", "");
    try {
      const claims = jwt.verify(token, cert);
      const policy = generatePolicy(claims.sub, event.routeArn);
      return {
        ...policy,
        context: claims,
      };
    } catch (error) {
      throw createError.Unauthorized();
    }
  }
};