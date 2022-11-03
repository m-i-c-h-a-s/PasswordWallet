const crypto = require("crypto");
const secret = "ghijkl09876543211234567890abcdef";
const salt = "1234567890abcdef";

const encryptSHA = (password) => {
  const saltMaster = crypto.randomBytes(16).toString("hex");
  const hash = crypto
    .pbkdf2Sync(password, saltMaster, 1000, 64, `sha512`)
    .toString(`hex`);

  return {
    salt: saltMaster.toString("hex"),
    password: hash.toString("hex"),
  };
};

const validateSHA = (password, salt, hash) => {
  var hash_temp = crypto
    .pbkdf2Sync(password, salt, 1000, 64, `sha512`)
    .toString(`hex`);
  return hash_temp === hash;
};

const encryptHMAC = (password) => {
  return crypto.createHmac("sha256", secret).update(password).digest("hex");
};

const encrypt = (plain) => {
  let cipher = crypto.createCipheriv("aes-256-cbc", secret, salt);
  let encrypted = cipher.update(plain, "utf8", "base64");
  encrypted += cipher.final("base64");
  return encrypted;
};

const decrypt = (encrypted) => {
  encrypted = encrypted.toString();
  let decipher = crypto.createDecipheriv("aes-256-cbc", secret, salt);
  let decrypted = decipher.update(encrypted, "base64", "utf8");
  return decrypted + decipher.final("utf8");
};

module.exports = {
  encrypt,
  decrypt,
  encryptSHA,
  encryptHMAC,
  validateSHA,
};