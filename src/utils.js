const { v4 } = require("uuid");
const jwt = require("jsonwebtoken");

const uuid = () => {
  const id = v4();
  return id.toString().split("-").join("");
};

const verifyJwtToken = (token, secretKey) => {
  return new Promise((resolve, reject) => {
    jwt.verify(token, secretKey, (err, decoded) => {
      if (err) {
        return reject(err);
      }
      resolve(decoded);
    });
  });
};

module.exports = {
  uuid,
  verifyJwtToken,
};
