// VULNERABLE: Hardcoded secrets (test fixture - DO NOT use in production)

const config = {
  database: {
    password: "my_super_secret_db_password",
    connectionString: "postgres://admin:password123@db.example.com/prod"
  },
  jwt: {
    secret: "jwt_secret_key_12345678901234567890",
  },
  aws: {
    accessKeyId: "AKIAIOSFODNN7EXAMPLE",
    secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
  }
};

// A07: JWT without verification
const jwt = require('jsonwebtoken');
function getUser(token) {
  return jwt.decode(token); // Missing jwt.verify()!
}
