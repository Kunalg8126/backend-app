require("dotenv").config();

const cors = require("cors");

const express = require("express");
const mongoose = require("mongoose");
const authRoutes = require("./route/auth");

const app = express();

app.use(cors({
  origin: 'https://app.netlify.com',
  credenatials: true,
}));
app.use(express.json());

app.use("/api", authRoutes);


mongoose.connect(process.env.MONGO_URL, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => {
    console.log("MongoDB connected");
    app.listen(process.env.PORT || 7000, () => {
      console.log(`Server running on port ${process.env.PORT || 7000}`);
    });
  })
  .catch((err) => console.log("MongoDB Connection Error:", err));

