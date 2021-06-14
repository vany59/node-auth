const mongoose = require("mongoose");
const { Schema, model } = mongoose;
const { uuid } = require("./utils");

const userSchema = new Schema({
  _id: String,
  username: String,
  password: String,
  refreshToken: String,
  accessToken: String,
});

userSchema.pre("save", function (next) {
  this._id = this._id || uuid();
  next();
});

const User = model("user", userSchema);
module.exports = {
  User,
};
