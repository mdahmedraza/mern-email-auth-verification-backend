require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const userRoute = require("./routes/userRoute");
const errorHandler = require("./middleware/errorMiddleware");

const app = express();

// middleware
app.use(express.json());
app.use(express.urlencoded({extended: false}));
app.use(cookieParser());
app.use(bodyParser.json());

app.use(
    cors({
        origin: ["http://localhost:3000", "https://authz-app.vercel.app"],
        credentials: true
    })
);

// routes
app.use("/api/users", userRoute);

app.get("/", (req, res) => {
    res.send("home page");
})

// error handler
app.use(errorHandler);

const PORT = process.env.PORT || 5000;
mongoose
    .connect(process.env.MONGO_URI)
    .then(() => {
        app.listen(PORT, () => {
            console.log(`server running on ${PORT}`);
        })
    })
    .catch((err) => console.log(err));