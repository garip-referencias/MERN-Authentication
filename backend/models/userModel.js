const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const validator = require("validator");

const Schema = mongoose.Schema;

const userSchema = new Schema({
  email: {
    type: String,
    required: true,
    unique: true,
  },
  password: {
    type: String,
    required: true,
  },
});

// - La palabra --> statics<-- es propia de la libreria mongoose y se usa para definir o invocar una funcion al modelo de datos.
// - Se utiliza function y no arrow function porque necesito usar la key --> this <-- adentro, y solo puedo hacerlo
//      en las regulars functions

userSchema.statics.signup = async function (email, password) {
  if (!email || !password) {
    throw Error("All field must be filled");
  }

  if (!validator.isEmail(email)) {
    throw new Error("Email is not valid");
  }

  if (!validator.isStrongPassword(password)) {
    throw new Error("Password not strong enough");
  }

  // se usa el this en vez de User, debido a que el objeto se exporta y en este ambito aun no esta creado

  const exists = await this.findOne({email});

  if (exists) {
    throw Error("Email already in use");
  }

  const salt = await bcrypt.genSalt(10);
  const hash = await bcrypt.hash(password, salt);

  const user = await this.create({email, password: hash});

  return user;
};

// static login method
userSchema.statics.login = async function (email, password) {
  // validation
  if (!email || !password) {
    throw Error("All field must be filled");
  }

  const user = await this.findOne({email});
  if (!user) {
    throw Error("Incorrect email");
  }

  const match = await bcrypt.compare(password, user.password);

  if (!match) {
    throw Error("Incorrect password");
  }

  return user;
};

module.exports = mongoose.model("User", userSchema);
