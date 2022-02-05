import express from "express";
import {
  GetUsername,
  GetEmail,
  GenerateHash,
  AddUsers,
  SetTokenandExpiryTime,
  FindUserWithTokenandId,
  UpdatePassword,
  SendMail,
  GetUserById,
} from "../functions/Function.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import { auth } from "../middleware/Auth.js";

const router = express.Router();

// REGISTER ROUTES:
router.route("/register").post(async (req, res) => {
  const dataProvided = req.body;

  // VERIFYING CREDENTIALS IN DB IF THEY ARE ALREADY USED OR NOT:
  const UsernameFrmDB = await GetUsername(dataProvided.username);
  const emailFrmDB = await GetEmail(dataProvided.email);

  // CREDENTIALS VERIFICATION CONDITIONS:
  if (UsernameFrmDB && emailFrmDB) {
    res.status(400).send({ message: "Username and Email already exists" });
    return;
  }

  if (UsernameFrmDB) {
    res.status(400).send({ message: "Username already exists" });
    return;
  }
  if (emailFrmDB) {
    res.status(400).send({ message: "User Email already exists" });
    return;
  }

  if (dataProvided.password.length < 8) {
    res.status(400).send({ message: "Password must be longer" });
    return;
  }

  if (
    !/^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@!#%&]).{8,}$/g.test(
      dataProvided.password
    )
  ) {
    res.status(400).send({ message: "Password pattern doesn't match" });
    return;
  }

  if (
    !/^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/.test(
      dataProvided.email
    )
  ) {
    res.status(400).send({ message: "Email pattern doesn't match" });
    return;
  }

  // IF CREDENTIAL PASS THE VERIFIACTION METHODS THEN HASHING THE PASSWORD:
  const hashedPassword = await GenerateHash(dataProvided.password);

  // ADDING THE NEW USER TO DATABASE:
  const result = await AddUsers(
    dataProvided.lname,
    dataProvided.fname,
    dataProvided.username,
    hashedPassword,
    dataProvided.email,
    dataProvided.userType
  );

  // SENDING THE RESPONSE:
  res.send(result);
});

// END POINTS FOR THE LOGIN:
router.route("/login").post(async (req, res) => {
  const dataProvided = req.body;

  // GETTING THE USER DETAILS FROM DB:
  const DataFrmDB = await GetUsername(dataProvided.username);

  // ERROR MESSAGE RESPONSE IF THE USER IS NOT PRESENT IN THE DB:
  if (!DataFrmDB) {
    res.status(400).send({ message: "Invalid credentials", Access: false });
    return;
  }

  // IF THE USER PRESENT THEN PASSWORD IS COMPARED AND VERIFIED:
  const storedPassword = DataFrmDB.password;
  const isPasswordMatch = await bcrypt.compare(
    dataProvided.password,
    storedPassword
  );

  // CREATION OF LOGIN TOKEN:
  const tokenId = {
    id: DataFrmDB._id,
  };

  if (isPasswordMatch) {
    const token = jwt.sign({ id: tokenId }, process.env.SECRET_KEY);

    res.send({
      message: "Successfull login",
      token: token,
      Access: true,
    });
  } else {
    res.status(401).send({ message: "Invalid credentials", Access: false });
  }
});

// END POINT FOR CHECKING IF THE TOKEN IS CORRECT TO ALLOW PROTECTED ROUTES:
router.route("/verify-login-token").post(auth, (req, res) => {
  const token = req.header("x-auth-token");

  // VERIFYING THE TOKEN SENT FROM CLIENT SIDE:
  jwt.verify(token, process.env.SECRET_KEY, () => {
    res.send({ message: "Token verification successfull", Access: true });
  });
});

// END POINTS FOR THE RESET PASSWORD:
router.route("/send-mail").post((req, res) => {
  // CREATION OF TOKEN USING NODE JS INBUILD MODULE:
  crypto.randomBytes(32, async (err, buffer) => {
    const token = buffer.toString("hex");

    // VERIFYING THE EMAIL ENTERED BY THE USER:
    const dataProvided = req.body;
    const emailFromDB = await GetEmail(dataProvided.email);

    // THROWING AN ERROR IF THE EMAIL IS NOT PRESENT IN THE DB:
    if (!emailFromDB) {
      return res.status(422).send({
        message: "User doesn't exist with that E-mail",
        Access: false,
      });
    }

    // AFTER PASSING THE EMAIL VERIFICATION:
    // ASSIGNING EXPIRATION TIME FOR THE TOKEN:
    const email = emailFromDB.email;
    const tokenExpire = new Date();
    tokenExpire.setMinutes(tokenExpire.getMinutes() + 10);

    SetTokenandExpiryTime(token, tokenExpire.toString(), email);

    // TO SEND AN AUTOMATIC EMAIL WITH AN LINK TO THE RESET PASSWORD PAGE:
    const subject = "Reset Password";
    const content = ` <h1>You requested for a password change</h1>
            <h3>Click on this <a href="https://61fbe8e7f4a40a00084ce1c8--flamboyant-sammet-290c35.netlify.app/reset-password/${emailFromDB._id}/${token}">link</a> to reset your password</h3>
            `;
    SendMail(emailFromDB.email, subject, content);

    res.send({ message: "Mail successfully sent to the user", Access: true });
  });
});

// VERIFYING THE LINK SENT THROUGH THE MAIL IF IT IS EXPIRED:
router.route("/reset-password/:id/:token").get(async (req, res) => {
  const { id, token } = req.params;
  const userData = await GetUserById(id);

  function isexpired() {
    if (userData.expireTime && userData.expireTime > new Date().toString()) {
      return true;
    } else {
      return false;
    }
  }

  if (
    (userData.token && userData.token !== token) ||
    !isexpired() ||
    !userData.token
  ) {
    return res.send({
      message: "Session expired, retry password reset",
      Access: false,
    });
  }

  // SENDING AN RESPONSE IF THE TOKEN IS NT EXPIRED:
  res.send({ message: "verified", Access: true });
});

// END POINTS FOR UPDATING NEW PASSWORD:
router.route("/reset-password").post(async (req, res) => {
  const dataProvided = req.body;

  // DATA FROM CLIENT SIDE TO FILTER THE USER;
  const newPassword = dataProvided.password;
  const token = dataProvided.token;
  const id = dataProvided.id;

  const user = await FindUserWithTokenandId(token, id);
  if (!user) {
    return res
      .status(422)
      .send({ message: "Try again session expired", Access: false });
  }

  // HASHING THE NEW PASSWORD AND UPDATING IT IN THE DB:
  // ALSO DELETING THE TOKEN CREATED FOR PASSWORD RESET:
  bcrypt.hash(newPassword, 10).then(async (hashedPassword) => {
    const passwordChanged = await UpdatePassword(hashedPassword, id);
    if (passwordChanged.modifiedCount) {
      return res.send({
        message: "Password successfully updated",
        Access: true,
      });
    }
    res.send({ message: "Password updation failed", Access: false });
  });
});

export const userRouter = router;
