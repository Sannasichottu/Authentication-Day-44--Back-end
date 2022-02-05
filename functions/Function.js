import bcrypt from "bcrypt";
import { client } from "../index.js";
import { transporter } from "./SendEmail.js";
import { ObjectId } from "mongodb";

// TO GET USER FROM DATABASE BASED ON THE USERNAME:
function GetUsername(username) {
  return client
    .db("session44")
    .collection("userDetails")
    .findOne({ username: username });
}

// TO GET USER FROM DATABASE BASED ON THE EMAIL:
function GetEmail(email) {
  return client
    .db("session44")
    .collection("userDetails")
    .findOne({ email: email });
}

// TO HASH THE PASSWORD:
async function GenerateHash(password) {
  const NO_OF_ROUNDS = 10;
  const salt = await bcrypt.genSalt(NO_OF_ROUNDS);
  const hashedPassword = await bcrypt.hash(password, salt);
  return hashedPassword;
}

// TO ADD NEW USER TO DB:
function AddUsers(lname, fname, username, hashedPassword, email, userType) {
  return client
    .db("session44")
    .collection("userDetails")
    .insertMany([
      { lname, fname, username, password: hashedPassword, email, userType },
    ]);
}

// TO UPDATE THE USESR WITH TOKEN AND EXPIRY TIME FOR THE UPDATION OF NEW PASSWORD:
function SetTokenandExpiryTime(token, expireTime, email) {
  return client
    .db("session44")
    .collection("userDetails")
    .updateOne(
      { email: email },
      { $set: { token: token, expireTime: expireTime } }
    );
}

// FILTERING THE USER WITH ID AND TOKEN:
function FindUserWithTokenandId(token, id) {
  return client
    .db("session44")
    .collection("userDetails")
    .findOne({
      _id: ObjectId(id),
      token: token,
      expireTime: { $gt: new Date().toString() },
    });
}

// UPDATING THE NEW PASSWORD IN THE DB:
function UpdatePassword(hashedPassword, id) {
  return client
    .db("session44")
    .collection("userDetails")
    .updateOne(
      {
        _id: ObjectId(id),
      },
      {
        $set: {
          password: hashedPassword,
        },
        $unset: { token: 1, expireTime: 1 },
      }
    );
}

// TO SEND AN EMAIL WHEN NEW CONTACTS, SERVICE REQUESTS OR LEADS ADDED:
function SendMail(email, subject, content) {
  transporter.sendMail({
    to: email,
    from: "ragavofficial01@outlook.com",
    subject: subject,
    html: content,
  });
}

// TO VERIFY THE TOKEN SENT THROUGH MAIL:
function GetUserById(id) {
  return client
    .db("session44")
    .collection("userDetails")
    .findOne({ _id: ObjectId(id) });
}

export {
  GetUsername,
  GetEmail,
  GenerateHash,
  AddUsers,
  SetTokenandExpiryTime,
  FindUserWithTokenandId,
  UpdatePassword,
  SendMail,
  GetUserById,
};
