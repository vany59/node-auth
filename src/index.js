const express = require("express");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
var bcrypt = require("bcryptjs");
const mongoose = require("mongoose");
const { User } = require("./user.schema");
const { verifyJwtToken } = require("./utils");
const {
  TOKENLIFE,
  REFESHTOKENLIFE,
  ACCESS_SECRET,
  REFRESH_SECRET,
} = require("./constant");

const router = express.Router();
const app = express();

//connect db
mongoose.connect(process.env.DB_HOST, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

app.use(bodyParser.json());
app.use("/api", router);
app.listen(process.env.PORT || 5000, () => {
  console.log("server is running");
});

router.post("/signup", async (req, res) => {
  const { username, password } = req.body;
  const existedUser = await User.findOne({ username });
  if (existedUser) {
    res.json({
      error: "Account existed",
    });
    return;
  }
  const token = jwt.sign({ username }, ACCESS_SECRET, {
    expiresIn: TOKENLIFE,
  });

  const refreshToken = jwt.sign({ username }, REFRESH_SECRET, {
    expiresIn: REFESHTOKENLIFE,
  });

  const hashPassword = bcrypt.hashSync(password, 10);
  const newUser = new User({
    username,
    password: hashPassword,
    token,
    refreshToken,
  });
  await newUser.save();
  res.json({
    code: 200,
    data: {
      token,
      refreshToken,
    },
  });
});

router.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const token = jwt.sign({ username }, ACCESS_SECRET, {
    expiresIn: TOKENLIFE,
  });

  const refreshToken = jwt.sign({ username }, REFRESH_SECRET, {
    expiresIn: REFESHTOKENLIFE,
  });

  const existedUser = await User.findOne({ username });
  if (!existedUser) {
    res.json({ code: 500, error: "login fail" });
    return;
  }
  const isCorectPassword = bcrypt.compareSync(password, existedUser.password);
  if (!isCorectPassword) {
    res.json({ code: 500, error: "login fail" });
    return;
  }
  await existedUser.update({ refreshToken });

  res.json({
    code: 200,
    data: {
      token,
      refreshToken,
    },
  });
});

const authMiddleware = (req, res, next) => {
  const bearerHeader = req.headers["authorization"];

  if (bearerHeader) {
    const bearer = bearerHeader.split(" ");
    const bearerToken = bearer[1];
    const token = bearerToken;
    verifyJwtToken(token, ACCESS_SECRET)
      .then((data) => {
        next();
      })
      .catch((e) => {
        res.json({
          code: 403,
          error: "token expired",
        });
        console.dir(e);
        return;
      });
  } else {
    res.json({
      code: 401,
      error: "not found token",
    });
  }
};

router.post("/refresh-token", async (req, res) => {
  const { refreshToken } = req.body;
  const user = await User.findOne({ refreshToken });
  if (user) {
    verifyJwtToken(refreshToken, REFRESH_SECRET)
      .then(async (data) => {
        const { username } = data;
        const token = jwt.sign({ username }, ACCESS_SECRET, {
          expiresIn: TOKENLIFE,
        });

        const refreshToken = jwt.sign({ username }, REFRESH_SECRET, {
          expiresIn: REFESHTOKENLIFE,
        });
        // await User.findOneAndUpdate(user, { refreshToken });
        await user.update({ refreshToken });
        res.json({
          code: 200,
          data: {
            token,
            refreshToken,
          },
        });
      })
      .catch(() => {
        res.json({
          code: 403,
          error: "refresh token expired",
        });
      });
  } else {
    res.json({
      code: 403,
      error: "refresh token error",
    });
  }
});

router.get("/data", authMiddleware, (req, res) => {
  res.json({
    code: 200,
    data: "ok",
  });
});
