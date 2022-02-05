import express from "express";
import dotenv from "dotenv";
import { MongoClient } from "mongodb";
import cors from "cors";
import { userRouter } from "./routes/Users.js";

dotenv.config();

const app = express();
const PORT = process.env.PORT;
const MONGO_URL = process.env.MONGO_URL;

async function CreateConnection() {
  const client = new MongoClient(MONGO_URL);
  await client.connect();
  console.log("Mongo DB Connected");
  return client;
}
export const client = await CreateConnection();

app.use(cors());
app.use(express.json());

app.use("/", userRouter);

app.get("/", (req, res) => {
  res.send("WELCOME TO PASSWORD RESET FLOW");
});

app.listen(PORT, () => {
  console.log("Server Started in", PORT);
});
